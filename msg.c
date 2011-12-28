/*
 * Copyright 2011 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "autotools-config.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <jansson.h>
#include <openssl/sha.h>
#include <syslog.h>
#include "server.h"

struct work_aux;

struct work_src
{
	unsigned char data[128];
	unsigned char *coinbase;
	size_t coinbase_len;
	unsigned char *merkle;
	struct work_aux **auxworks;
	unsigned int merkle_len;
	unsigned int script_off, script_len, ournonce_off;

	unsigned char *aux_merkle;
	unsigned int aux_merkle_depth;
	uint32_t aux_merkle_nonce;

	unsigned int refcnt;
};

struct work_aux
{
	unsigned char hash[32];
	unsigned char prevhash[32];
	struct server_auxchain *aux;
	int32_t chain_id;

	unsigned int refcnt;
};

struct worker {
	char			username[64 + 1];

	struct elist_head	log;
};

struct work_ent {
	char			data[128];

	time_t			timestamp;
	uint32_t		our_nonce;
	struct work_src*	src;

	struct elist_head	log_node;
	struct elist_head	srv_log_node;
};

static const char *bc_err_str[] = {
	[BC_ERR_NONE] = "no error (success)",
	[BC_ERR_INVALID] = "invalid parameter",
	[BC_ERR_AUTH] = "auth failed: invalid user or pass",
	[BC_ERR_CONFIG] = "invalid configuration",
	[BC_ERR_RPC] = "upstream RPC problem",
	[BC_ERR_WORK_REJECT] = "work submit rejected upstream",
	[BC_ERR_INTERNAL] = "internal server err",
};

static struct work_aux *work_aux_alloc(struct server_auxchain *aux) {
	struct work_aux *work = calloc(1, sizeof(struct work_aux));
	work->aux = aux;
	work->refcnt = 1;
	return work;
}

static void work_aux_incref(struct work_aux *work) {
	work->refcnt++;
}

static void work_aux_decref(struct work_aux *work) {
	if(--(work->refcnt) == 0) {
		free(work);
	}	
}


static struct work_src *work_src_alloc(void) {
	struct work_src *work = calloc(1, sizeof(struct work_src));
	work->coinbase = NULL;
	work->merkle = NULL;
	work->aux_merkle = NULL;
	work->refcnt = 1;
	return work;
}

static void work_src_incref(struct work_src *work) {
	work->refcnt++;
}

static void work_src_decref(struct work_src *work) {
	if(--(work->refcnt) == 0) {
		if(work->auxworks) {
			struct work_aux **pauxwork;
			for(pauxwork = work->auxworks; *pauxwork != NULL; pauxwork++)
				work_aux_decref(*pauxwork);
			free(work->auxworks);
		}
		free(work->coinbase);
		free(work->merkle);
		free(work->aux_merkle);
		free(work);
	}	
}


char *pwdb_lookup(const char *user)
{
	char *pass = NULL;
	char cred_key[256];
	uint32_t out_flags;
	size_t out_len;
	memcached_return_t rc;

	if (srv.mc) {
		snprintf(cred_key, sizeof(cred_key),
			 "/pushpoold/cred_cache/%s", user);

		pass = memcached_get(srv.mc, cred_key, strlen(cred_key),
				     &out_len, &out_flags, &rc);
		if (rc == MEMCACHED_SUCCESS)
			return pass;		/* may be NULL, for negative caching */
	}

	pass = srv.db_ops->pwdb_lookup(user);

	if (srv.mc) {
		rc = memcached_set(srv.mc, cred_key, strlen(cred_key) ,
				   pass,
				   pass ? strlen(pass) + 1 : 0,
				   srv.cred_expire, 0);
		if (rc != MEMCACHED_SUCCESS)
			applog(LOG_WARNING, "memcached store(%s) failed: %s",
			       cred_key, memcached_strerror(srv.mc, rc));
	}

	return pass;
}

void worker_log_expire(time_t expire_time)
{
	struct work_ent *ent, *iter;

	elist_for_each_entry_safe(ent, iter, &srv.work_log, srv_log_node) {
		if (ent->timestamp > expire_time)
			break;
		if(ent->src != NULL)
			work_src_decref(ent->src);
		elist_del(&ent->srv_log_node);
		elist_del(&ent->log_node);
		free(ent);
	}
}

static void worker_log(const char *username, const unsigned char *data,
                       uint32_t our_nonce, struct work_src *src)
{
	struct worker *worker;
	struct work_ent *ent;
	time_t now = time(NULL);

	worker = htab_get(srv.workers, username);
	if (!worker) {
		worker = calloc(1, sizeof(*worker));
		if (!worker)
			return;

		strncpy(worker->username, username, sizeof(worker->username));
		INIT_ELIST_HEAD(&worker->log);

		if (!htab_put(srv.workers, worker->username, worker))
			return;
	}

	ent = calloc(1, sizeof(*ent));
	if (!ent)
		return;

	memcpy(ent->data, data, sizeof(ent->data));
	ent->timestamp = now;
	ent->our_nonce = our_nonce;
	if(src != NULL)
		work_src_incref(src);
	ent->src = src;
	INIT_ELIST_HEAD(&ent->log_node);
	INIT_ELIST_HEAD(&ent->srv_log_node);

	elist_add_tail(&ent->log_node, &worker->log);
	elist_add_tail(&ent->srv_log_node, &srv.work_log);

	worker_log_expire(now - srv.work_expire);
}

static const char *work_in_log(const char *username, const unsigned char *data,
                               uint32_t *our_nonce_out, struct work_src **work_src_out)
{
	struct worker *worker;
	struct work_ent *ent;

	worker = htab_get(srv.workers, username);
	if (!worker)
		return "unknown-user";

	elist_for_each_entry(ent, &worker->log, log_node) {
		/* check submitted block matches sent block,
		 * excluding timestamp and nonce
		 */
		if (!memcmp(ent->data, data, 68) && !memcmp(ent->data + 72, data + 72, 4))
		{
			*our_nonce_out = ent->our_nonce;
			*work_src_out = ent->src;

			/* verify timestamp is within reasonable range
			*/
			uint32_t timestampSent = ntohl(*(uint32_t*)(ent->data + 68));
			uint32_t timestampRcvd = ntohl(*(uint32_t*)(     data + 68));
			if (timestampRcvd == timestampSent)
				return NULL;
			if (srv.disable_roll_ntime)
				return "time-invalid";
			time_t now = time(NULL);
			if (timestampRcvd < now - 300)
				return "time-too-old";
			if (timestampRcvd > now + 7200)
				return "time-too-new";
			return NULL;
		}
	}

	return "unknown-work";
}

static const char *stale_work(const unsigned char *data)
{
	if (!memcmp(data + 4, srv.cur_prevhash, sizeof(srv.cur_prevhash)))
		return NULL;
	if (!memcmp(data + 4, srv.last_prevhash, sizeof(srv.last_prevhash)))
		return "prevhash-stale";
	return "prevhash-wrong";
}

static bool jobj_binary(const json_t *obj, const char *key,
			void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (!tmp) {
		return false;
	}
	hexstr = json_string_value(tmp);
	if (!hexstr) {
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool work_decode(const json_t *val, struct bc_work *work)
{
	if (!jobj_binary(val, "midstate",
			 work->midstate, sizeof(work->midstate))) {
		goto err_out;
	}

	if (!jobj_binary(val, "data", work->data, sizeof(work->data))) {
		goto err_out;
	}

	if (!jobj_binary(val, "hash1", work->hash1, sizeof(work->hash1))) {
		goto err_out;
	}

	if (!jobj_binary(val, "target", work->target, sizeof(work->target))) {
		goto err_out;
	}

	return true;

err_out:
	return false;
}

// rebuilds the merkle tree and block header after modifying the coinbase
static void rebuild_merkle_tree(struct work_src* work, unsigned char data_out[128])
{
	unsigned char merkle_buf[SHA256_DIGEST_LENGTH*2];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	unsigned int i;
	uint32_t *hash32 = (uint32_t *)merkle_buf;
	memcpy(data_out, work->data, 128);
	SHA256(work->coinbase, work->coinbase_len, hash);
	SHA256(hash, SHA256_DIGEST_LENGTH, merkle_buf);
	for(i = 0; i < work->merkle_len; i++) {
		memcpy(merkle_buf+SHA256_DIGEST_LENGTH,
		       work->merkle+i*SHA256_DIGEST_LENGTH,
		       SHA256_DIGEST_LENGTH);
		SHA256(merkle_buf, SHA256_DIGEST_LENGTH*2, hash);
		SHA256(hash, SHA256_DIGEST_LENGTH, merkle_buf);
	}
	for(i = 0; i < 8; i++)
		hash32[i] = bswap_32(hash32[i]);
	memcpy(data_out+36, merkle_buf, SHA256_DIGEST_LENGTH);
}

// sets the value of the nonce added by amend_coinbase
static void set_our_nonce(struct work_src* work, uint32_t our_nonce) {
	union { uint32_t i; unsigned char c[4]; } u;
	u.i = our_nonce;
	memcpy(work->coinbase+work->ournonce_off, u.c, 4);
}

static unsigned int rpcid = 1;

static struct work_src *current_work = NULL;
static uint32_t our_nonce_ctr = 0;
static time_t current_work_expires = 0;

static void calc_midstate(unsigned char *data, uint32_t *midstate_out)
{
	uint32_t data_fixed[16]; int i;
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	memcpy(data_fixed, data, 64);
	for(i = 0; i < 16; i++)
		data_fixed[i] = bswap_32(data_fixed[i]);
	SHA256_Update(&ctx, data_fixed, 64);
	
	// we can't use memcpy here because SHA_LONG may not be 32-bits
	for(i = 0; i < 8; i++)
		midstate_out[i] = ctx.h[i];
}

static json_t *get_work(const char *auth_user)
{
	char s[80];
	unsigned char data[128];
	const char *data_str;
	json_t *val, *result;

	if(current_work != NULL && time(NULL) > current_work_expires)
		fetch_new_work();

	if(current_work != NULL && !srv.disable_lp && srv.easy_target) {
		uint32_t our_nonce = our_nonce_ctr++;
		uint32_t midstate[8];
		set_our_nonce(current_work, our_nonce);
		rebuild_merkle_tree(current_work, data);

		val = json_object();
		result = json_object();
		json_object_set_new(val, "result", result);
		data_str = bin2hex(data, 128);
		json_object_set_new(result, "data", json_string(data_str));
		free(data_str);

		calc_midstate(data, midstate);
		data_str = bin2hex((unsigned char*)midstate, 32);
		json_object_set_new(result, "midstate", json_string(data_str));
		free(data_str);
		json_object_set_new(result, "hash1", json_string("00000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000010000"));
		json_object_set(result, "target", srv.easy_target);

		/* log work unit as having been sent to associated worker */
		worker_log(auth_user, data, our_nonce, current_work);
	} else {
		sprintf(s, "{\"method\": \"getwork\", \"params\": [], \"id\":%u}\r\n",
			rpcid++);

		/* issue JSON-RPC request */
		val = json_rpc_call(srv.curl, srv.rpc_url, srv.rpc_userpass, s);
		if (!val)
			return NULL;

		/* decode data field, implicitly verifying 'result' is an object */
		result = json_object_get(val, "result");
		data_str = json_string_value(json_object_get(result, "data"));
		if (!data_str ||
		    !hex2bin(data, data_str, sizeof(data))) {
			json_decref(val);
			return NULL;
		}

		if (memcmp(data + 4, srv.cur_prevhash, sizeof(srv.cur_prevhash)))
		{
			/* store two most recently seen prevhash (last, and current) */
			memcpy(srv.last_prevhash, srv.cur_prevhash, sizeof(srv.last_prevhash));
			memcpy(srv.cur_prevhash, data + 4, sizeof(srv.cur_prevhash));
		}

		/* log work unit as having been sent to associated worker */
		worker_log(auth_user, data, 0, NULL);

		/* rewrite target (pool server mode), if requested in config file */
		if (srv.easy_target)
			json_object_set(result, "target", srv.easy_target);
	}
	return val;
}

static const unsigned char expect_coinbase[41] = { 1, 0, 0, 0, 1 };

static const unsigned char pchMergedMiningHeader[] = { 0xfa, 0xbe, 'm', 'm' } ;

// appends a new nonce to the coinbase that can be set by set_our_nonce
static bool amend_coinbase(struct work_src *work, unsigned char *auxmerkleroot,
                           uint32_t auxmerklesize, uint32_t auxmerklenonce)
{
	unsigned char *new_coinbase;
	unsigned int script_end;
	unsigned int size_increase = auxmerklesize > 0 ? (46 + 5) : 5;

	// validate coinbase looks as expected
	if(work->coinbase_len < 47 || 
	   memcmp(work->coinbase, expect_coinbase, sizeof(expect_coinbase) != 0))
		return false;
	if(work->coinbase[41] >= 0xfd)
		return false;
	work->script_off = 42;
	work->script_len = work->coinbase[41];
	script_end = work->script_off+work->script_len;
	if(script_end >= work->coinbase_len)
		return false;
	
	// check we have space to add another nonce without
	// having to muck around with varints
	if(work->script_len >= 0xfd-size_increase)
		return false;

	// prepare to add the extra data at the end of scriptSig
	new_coinbase = malloc(work->coinbase_len + size_increase);
	memcpy(new_coinbase, work->coinbase, script_end);
	memcpy(new_coinbase+script_end+size_increase, work->coinbase+script_end,
	       work->coinbase_len - script_end);
	work->ournonce_off = script_end+1;
	work->script_len += size_increase;
	new_coinbase[41] = work->script_len;

	if(auxmerklesize > 0) {
		// add the merged mining data
		new_coinbase[script_end] = 82; // OP_2
		new_coinbase[script_end+1] = 44; // length of MM data
		memcpy(new_coinbase+script_end+2, pchMergedMiningHeader, 4);
		memcpy(new_coinbase+script_end+6, auxmerkleroot, 32);
		memcpy(new_coinbase+script_end+38, &auxmerklesize, 4);
		memcpy(new_coinbase+script_end+42, &auxmerklenonce, 4);
		script_end += 46;
	}

	// add the extranonce
	new_coinbase[script_end] = 0x4;
	memset(new_coinbase+script_end+1, 0, 4);
	
	// replace the coinbase with the amended version
	free(work->coinbase);
	work->coinbase = new_coinbase;
	work->coinbase_len += size_increase;
	
	return true;
}

// New, faster getworkex code that allows us to generate our own work
static struct work_src* get_work_ex(void)
{
	unsigned char data2[128];
	char s[80]; unsigned int i;
	struct work_src *work = work_src_alloc();
	const char *data_str, *coinbase_str;
	json_t *val, *result, *merkle_array;

	sprintf(s, "{\"method\": \"getworkex\", \"params\": [], \"id\":%u}\r\n",
		rpcid++);

	/* issue JSON-RPC request */
	val = json_rpc_call(srv.curl, srv.rpc_url, srv.rpc_userpass, s);
	if (!val)
		return NULL;

	/* decode data field, implicitly verifying 'result' is an object */
	result = json_object_get(val, "result");
	data_str = json_string_value(json_object_get(result, "data"));
	coinbase_str = json_string_value(json_object_get(result, "coinbase"));
	merkle_array = json_object_get(result, "merkle");
	if (!data_str || !coinbase_str || !merkle_array ||
	    !hex2bin(work->data, data_str, sizeof(work->data))) {
		json_decref(val);
		work_src_decref(work);
		return NULL;
	}
	work->coinbase_len = hex2bin_dyn(&work->coinbase, coinbase_str);
	if(work->coinbase_len == 0) {
		json_decref(val);
		work_src_decref(work);
		return NULL;
	}
	work->merkle_len = json_array_size(merkle_array);
	work->merkle = calloc(work->merkle_len, 32);
	for(i = 0; i < work->merkle_len; i++) {
		data_str = json_string_value(json_array_get(merkle_array, i));
		if(!data_str || !hex2bin(work->merkle+32*i, data_str, 32)) {
			json_decref(val);
			work_src_decref(work);
			return NULL;
		}
	}

	if (memcmp(work->data + 4, srv.cur_prevhash, sizeof(srv.cur_prevhash)))
	{
		/* store two most recently seen prevhash (last, and current) */
		memcpy(srv.last_prevhash, srv.cur_prevhash, sizeof(srv.last_prevhash));
		memcpy(srv.cur_prevhash, work->data + 4, sizeof(srv.cur_prevhash));
	}

	rebuild_merkle_tree(work, data2);
	if(memcmp(data2, work->data, 128) != 0)
		abort();

	json_decref(val);
	return work;
}

static struct work_aux* get_aux_block(struct server_auxchain *aux)
{
	//unsigned char block_hash[32];
	char s[80]; unsigned int i;
	struct work_aux *auxwork = work_aux_alloc(aux);
	const char *target_str, *hash_str, *prevhash_str;
	json_t *val, *result;

	sprintf(s, "{\"method\": \"getauxblock\", \"params\": [], \"id\":%u}\r\n",
		rpcid++);

	/* issue JSON-RPC request */
	val = json_rpc_call(srv.curl, aux->rpc_url, aux->rpc_userpass, s);
	if (!val)
		return NULL;

	/* decode data field, implicitly verifying 'result' is an object */
	result = json_object_get(val, "result");
	target_str = json_string_value(json_object_get(result, "target"));
	hash_str = json_string_value(json_object_get(result, "hash"));
	prevhash_str = json_string_value(json_object_get(result, "prevhash"));
	auxwork->chain_id = json_integer_value(json_object_get(result, "chainid"));
	if (!target_str || !hash_str || !prevhash_str ||
	    !hex2bin(auxwork->hash, hash_str, sizeof(auxwork->hash)) ||
	    !hex2bin(auxwork->prevhash, prevhash_str, sizeof(auxwork->prevhash))) {
		json_decref(val);
		work_aux_decref(auxwork);
		return NULL;
	}

	if (memcmp(auxwork->prevhash, aux->cur_prevhash, sizeof(aux->cur_prevhash)))
	{
		/* store two most recently seen prevhash (last, and current) */
		memcpy(aux->last_prevhash, aux->cur_prevhash, sizeof(aux->last_prevhash));
		memcpy(aux->cur_prevhash, auxwork->prevhash, sizeof(aux->cur_prevhash));
	}
	
	json_decref(val);
	return auxwork;
}

static int need_merkle_relayout = 1;
uint32_t aux_merkle_nonce = 0;
unsigned int aux_merkle_depth = 0;


static uint32_t calc_merkle_slot_namecoin(uint32_t nonce, uint32_t chain_id)
{
	uint32_t n = nonce * 1103515245 + 12345 + chain_id;
	return n * 1103515245 + 12345;
}

#define lrot(x,n) (((x) << (n)) | ((x) >> (32-(n))))

static uint32_t calc_merkle_slot_bob(uint32_t nonce, uint32_t chain_id)
{
	uint32_t n = (0xdeadbeef ^ chain_id) - lrot(chain_id, 14);
	nonce = (nonce ^ n) - lrot(n, 11);
	chain_id = (chain_id ^ nonce) - lrot(nonce, 25);
	n = (n ^ chain_id) - lrot(chain_id, 16);
	nonce = (nonce ^ n) - lrot(n, 4);
	chain_id = (chain_id ^ nonce) - lrot(nonce, 14);
	n = (n ^ chain_id) - lrot(chain_id, 24);
	return n;
}

uint32_t calc_aux_merkle_slot(uint32_t nonce, struct work_aux* auxwork) {
	return calc_merkle_slot_namecoin(nonce, auxwork->chain_id);
}

bool layout_aux_merkle_tree(unsigned int num_chains) {
	unsigned int i;
	bool success = false;
	for(aux_merkle_depth = 0; aux_merkle_depth < 10 && !success; aux_merkle_depth++) {
		unsigned int num_merkle_slots = 1 << aux_merkle_depth;
		if(num_chains > num_merkle_slots)
			continue;

		for(aux_merkle_nonce = 0; aux_merkle_nonce < 1000 && !success; aux_merkle_nonce++) {
			printf("DEBUG: trying %u slots with nonce %u\n", num_merkle_slots, aux_merkle_nonce);
			char merkle_used[num_merkle_slots];
			memset(merkle_used, 0, num_merkle_slots);
			success = true;
			for(i = 0; i < num_chains; i++) {
				unsigned int slot = calc_aux_merkle_slot(aux_merkle_nonce, current_work->auxworks[i]) & (num_merkle_slots - 1);
				if(merkle_used[slot])
					success = false;
				merkle_used[slot] = 1;
			}
			if(success) break;
		}
		if(success) break;
	}
	if(success)
		need_merkle_relayout = 0;
	return success;
}

static void reverse_copy_hash(unsigned char *dest, unsigned char *src)
{
	int i;
	for(i = 31; i >= 0; i--) *(dest++) = src[i];
}

void get_merkle_branch(unsigned char *merkle, unsigned int len, unsigned int idx,
		       unsigned char *branch_out) {
	unsigned int i;
	while(len > 1) {
		i = idx^1;
		if(i >= len) i = len - 1;
		memcpy(branch_out, merkle+32*i, 32);
		idx /= 2;
		branch_out += 32;
		merkle += 32 * len;
		len = (len + 1) / 2;
	}
}

void build_aux_merkle_tree(unsigned int num_chains, unsigned char auxmerkleroot[32])
{
	current_work->aux_merkle_depth = aux_merkle_depth;
	current_work->aux_merkle_nonce = aux_merkle_nonce;
	if(num_chains == 0)
	{
		memset(auxmerkleroot, 0, 32);
	} else {
		unsigned int i, j, n; unsigned char tmp[32];
		unsigned char* merkle_next;
		n = 1 << aux_merkle_depth;
		current_work->aux_merkle = calloc(n*2, 32);
		merkle_next = current_work->aux_merkle + n*32;
		for(i = 0; i < num_chains; i++) {
			j = calc_aux_merkle_slot(aux_merkle_nonce, current_work->auxworks[i]) & (n - 1);
			reverse_copy_hash(current_work->aux_merkle+32*j, current_work->auxworks[i]->hash);
		}
		for(i = 0; n > 1; n = (n + 1) / 2) {
			for(j = 0; j < n / 2; j++) {
				SHA256(current_work->aux_merkle+i*32+j*64, 64, tmp);
				SHA256(tmp, 32, merkle_next);
				merkle_next += 32;
			}
			i += n;
		}
		reverse_copy_hash(auxmerkleroot, merkle_next - 32);
		printf("DEBUG: aux merkle\n");
		for(i = 0; i < merkle_next - current_work->aux_merkle; i += 32) {
			char *s = bin2hex(current_work->aux_merkle+i, 32);
			printf("  %s\n", s);
			free(s);
		}			
	}
}

bool fetch_new_work(void)
{
	printf("DEBUG: fetch new work\n");
	if(current_work != NULL)
		work_src_decref(current_work);
	if(srv.disable_lp) {
		current_work = NULL;
		return false;
	} else {
		struct elist_head *tmpl;
		unsigned int num_chains = 0;
		int success = true;
		unsigned char auxmerkleroot[32];

		current_work = get_work_ex();
		current_work_expires = time(NULL) + 5;
		if(current_work == NULL)
			return false;

		elist_for_each(tmpl, &srv.auxchains)
			num_chains++;

		if(num_chains > 0) {
			current_work->auxworks = calloc(num_chains+1, sizeof(struct work_aux**));
		}

		num_chains = 0;
		elist_for_each(tmpl, &srv.auxchains) {
			struct server_auxchain *aux;
			struct work_aux* auxwork;

			aux = elist_entry(tmpl, struct server_auxchain, auxchains_node);
			auxwork = get_aux_block(aux);

			if(!auxwork) {
				success = false; continue;
			}

			if(aux->chain_id != auxwork->chain_id) {
				aux->chain_id = auxwork->chain_id;
				need_merkle_relayout = 1;
			}
			current_work->auxworks[num_chains++] = auxwork;
		}

		if(num_chains >= 1 && need_merkle_relayout) {
			layout_aux_merkle_tree(num_chains);
		}

		build_aux_merkle_tree(num_chains, auxmerkleroot);
		
		if(!amend_coinbase(current_work, auxmerkleroot, num_chains ? (1 << aux_merkle_depth) : 0, 
				   aux_merkle_nonce)) {
			work_src_decref(current_work);
			current_work = NULL;
			return false;
		}

		return success;
	}
}

static int check_hash(const char *remote_host, const char *auth_user,
		      const char *data_str, const char **reason_out,
                      uint32_t *our_nonce_out, struct work_src **work_src_out,
                      unsigned char *data_out, unsigned char *blockhash_out)
{
	unsigned char hash1[SHA256_DIGEST_LENGTH];
	uint32_t *hash32 = (uint32_t *) blockhash_out;
	uint32_t *data32 = (uint32_t *) data_out;
	bool rc, better_hash = false;
	int i;

	rc = hex2bin(data_out, data_str, 128);
	if (!rc) {
		applog(LOG_ERR, "check_hash hex2bin failed");
		return -1;		/* error; failure */
	}

	*reason_out = stale_work(data_out);
	if (*reason_out)
		return 0;		/* work is invalid */
	*reason_out = work_in_log(auth_user, data_out, our_nonce_out, work_src_out);
	if (*reason_out)
		return 0;		/* work is invalid */

	for (i = 0; i < 128/4; i++)
		data32[i] = bswap_32(data32[i]);

	SHA256(data_out, 80, hash1);
	SHA256(hash1, SHA256_DIGEST_LENGTH, blockhash_out);

	if (hash32[7] != 0) {
		*reason_out = "H-not-zero";
		return 0;		/* work is invalid */
	}
	if (blockhash_out[27] == 0)
		better_hash = true;

	if (hist_lookup(srv.hist, blockhash_out)) {
		*reason_out = "duplicate";
		return 0;		/* work is invalid */
	}
	if (!hist_add(srv.hist, blockhash_out)) {
		applog(LOG_ERR, "hist_add OOM");
		return -1;		/* error; failure */
	}

	return better_hash ? 2 : 1;			/* work is valid */
}

static bool submit_work_aux(const char *remote_host, const char *auth_user,
                            CURL *curl, const char *hexstr, 
                            struct work_src *work, struct work_aux *auxwork,
                            unsigned char *data, unsigned char *blockhash,
	                    int check_rc)
{
	json_t *val; int is_success = 0;
	char *request_str, *auxblock_hex, *auxpow_hex;
	unsigned char* auxpow, *p;
	unsigned int auxpow_len = work->coinbase_len + 32 + 1 + 32*work->merkle_len +
		4 + 1 + 32*work->aux_merkle_depth + 4 + 80;
	uint32_t aux_merkle_slot = calc_aux_merkle_slot(work->aux_merkle_nonce, auxwork) & ((1 << work->aux_merkle_depth) - 1);
	if(work->merkle_len > 32) 
		return false;
	
	if (memcmp(auxwork->prevhash, auxwork->aux->cur_prevhash,
	           sizeof(auxwork->prevhash))) {
		/* FIXME - check against last_prevhash for more accurate reason */
		sharelog(auxwork->aux, remote_host, auth_user, "N", NULL, "prevhash", hexstr);
		return false;
	}


	/* if hash is sufficient for share, but not target,
	 * don't bother submitting to bitcoind
	 */
	if (srv.easy_target && check_rc == 1) {
		sharelog(auxwork->aux, remote_host, auth_user, "Y", NULL, NULL, hexstr);
		return true;
	}

	auxpow = malloc(auxpow_len);
	memcpy(auxpow, work->coinbase, work->coinbase_len);
	p = auxpow + work->coinbase_len;
	memcpy(p, blockhash, 32); // parent block's hash
	p[32] = work->merkle_len;
	p += 33;
	memcpy(p, work->merkle, 32*work->merkle_len);
	p += 32*work->merkle_len;
	memset(p, 0, 4); // index of coinbase TX, currently always 0
	p[4] = work->aux_merkle_depth; // aux chain merkle branch length
	p += 5;
	get_merkle_branch(work->aux_merkle, 1 << work->aux_merkle_depth, aux_merkle_slot, p);
	p += 32*work->aux_merkle_depth;
	// FIXME: aux chain merkle branch goes here
	memcpy(p, &aux_merkle_slot, 4); // FIXME: aux chain merkle index goes here
	memcpy(p+4, data, 80); // parent block
	
	auxpow_hex = bin2hex(auxpow, auxpow_len);
	free(auxpow);

	auxblock_hex = bin2hex(auxwork->hash, 32);

	request_str = malloc(80+256+auxpow_len*2);
	sprintf(request_str, 
	        "{\"method\": \"getauxblock\", \"params\": [ \"%s\", \"%s\" ], \"id\":1}\r\n",
	        auxblock_hex, auxpow_hex);

	/* issue JSON-RPC request */
	val = json_rpc_call(curl, auxwork->aux->rpc_url, auxwork->aux->rpc_userpass,
	                   request_str);
	free(auxblock_hex);
	free(auxpow_hex);
	free(request_str);
	
	if (!val) {
		applog(LOG_ERR, "submit_work_aux json_rpc_call failed");
		goto out;
	}

	is_success = json_is_true(json_object_get(val, "result"));

	sharelog(auxwork->aux, remote_host, auth_user,
		 srv.easy_target ? "Y" : is_success ? "Y" : "N",
		 is_success ? "Y" : "N", NULL, hexstr);

	if(srv.easy_target)
		is_success = 1;

	json_decref(val);

out:
	return is_success;
}

static bool submit_work(const char *remote_host, const char *auth_user,
			CURL *curl, const char *hexstr, const char **reason)
{
	json_t *val;
	unsigned char data[128];
	unsigned char blockhash[SHA256_DIGEST_LENGTH];
	char s[256 + 80];
	bool rc = false;
	int check_rc;
	uint32_t our_nonce;
	struct work_src *work = NULL;
	*reason = NULL;

	/* validate submitted work */
	check_rc = check_hash(remote_host, auth_user, hexstr, reason, &our_nonce, &work,
	                      data, blockhash);
	if (check_rc < 0)	/* internal failure */
		goto out;
	if (check_rc == 0) {	/* invalid hash */
		sharelog(NULL, remote_host, auth_user, "N", NULL, *reason, hexstr);
		if(work && work->auxworks) {
			struct work_aux **pauxwork;
			for(pauxwork = work->auxworks; *pauxwork != NULL; pauxwork++)
				sharelog((*pauxwork)->aux, remote_host, auth_user,
					 "N", NULL, *reason, hexstr);
		}
		return true;
	}

	if(work) {
		/* set the nonce in work->coinbase to match this work item */
		set_our_nonce(work, our_nonce);
	}

	/* try submitting work to any aux chains */
	/* FIXME: we want to do this even if it's stale on the main chain */
	if(work && work->auxworks) {
		struct work_aux **pauxwork;
		for(pauxwork = work->auxworks; *pauxwork != NULL; pauxwork++)
			submit_work_aux(remote_host, auth_user, curl, hexstr,
					work, *pauxwork, data, blockhash,
				        check_rc);
	}

	/* if hash is sufficient for share, but not target,
	 * don't bother submitting to bitcoind
	 */
	if (srv.easy_target && check_rc == 1) {
		*reason = NULL;
		sharelog(NULL, remote_host, auth_user, "Y", NULL, NULL, hexstr);
		return true;
	}


	if(work)
	{
		char *hexstr_orig = bin2hex(work->data, 128);
		char *coinbase_hex;
		char *request_str;
		coinbase_hex = bin2hex(work->coinbase, work->coinbase_len);
		request_str = malloc(80+256+work->coinbase_len*2);
		
		/* copy across nTime and nonce */
		memcpy(hexstr_orig+136, hexstr+136, 24);

		sprintf(request_str, 
		        "{\"method\": \"getworkex\", \"params\": [ \"%s\", \"%s\" ], \"id\":1}\r\n",
		        hexstr_orig, coinbase_hex);

		/* issue JSON-RPC request */
		val = json_rpc_call(curl, srv.rpc_url, srv.rpc_userpass, request_str);
		free(hexstr_orig);
		free(coinbase_hex);
		free(request_str);
		
		if (!val) {
			applog(LOG_ERR, "submit_work json_rpc_call failed");
			goto out;
		}
	} else {
		/* build JSON-RPC request */
		sprintf(s,
		      "{\"method\": \"getwork\", \"params\": [ \"%s\" ], \"id\":1}\r\n",
			hexstr);
		
		/* issue JSON-RPC request */
		val = json_rpc_call(curl, srv.rpc_url, srv.rpc_userpass, s);
		if (!val) {
			applog(LOG_ERR, "submit_work json_rpc_call failed");
			goto out;
		}
	}

	*reason = json_is_true(json_object_get(val, "result")) ? NULL : "unknown";
	rc = true;

	sharelog(NULL, remote_host, auth_user,
		 srv.easy_target ? "Y" : *reason ? "N" : "Y",
		 *reason ? "N" : "Y", NULL, hexstr);

	if (debugging > 1)
		applog(LOG_INFO, "[%s] PROOF-OF-WORK submitted upstream.  "
		       "Result: %s",
		       remote_host,
		       *reason ? "false" : "TRUE");

	json_decref(val);

	if (!*reason)
		applog(LOG_INFO, "PROOF-OF-WORK found");

	/* if pool server mode, return success even if result==false */
	if (srv.easy_target)
		*reason = NULL;

out:
	return rc;
}

static bool submit_bin_work(const char *remote_host, const char *auth_user,
			    CURL *curl, void *data, const char **reason)
{
	char *hexstr = NULL;
	bool rc = false;

	/* build hex string */
	hexstr = bin2hex(data, 128);
	if (!hexstr) {
		applog(LOG_ERR, "submit_work OOM");
		goto out;
	}

	rc = submit_work(remote_host, auth_user, curl, hexstr, reason);

	free(hexstr);

out:
	return rc;
}

static bool cli_config(struct client *cli, const json_t *cfg)
{
	/* FIXME */
	return false;
}

bool cli_op_login(struct client *cli, const json_t *obj, unsigned int msgsz)
{
	char user[33];
	char *pass;
	json_t *cfg, *resobj, *res_cfgobj;
	int version, err_code = BC_ERR_INTERNAL;
	bool rc;
	SHA256_CTX ctx;
	unsigned char md[SHA256_DIGEST_LENGTH];

	/* verify client protocol version */
	version = json_integer_value(json_object_get(obj, "version"));
	if (version < 1 || version > 1) {
		err_code = BC_ERR_INVALID;
		goto err_out;
	}

	/* read username, and retrieve associated password from database */
	strncpy(user, json_string_value(json_object_get(obj, "user")),
		sizeof(user));
	user[sizeof(user) - 1] = 0;

	pass = pwdb_lookup(user);
	if (!pass) {
		applog(LOG_WARNING, "unknown user %s", user);
		err_code = BC_ERR_AUTH;
		goto err_out;
	}

	/* calculate sha256(login JSON packet + user password) */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, cli->msg, msgsz - SHA256_DIGEST_LENGTH);
	SHA256_Update(&ctx, pass, strlen(pass));
	SHA256_Final(md, &ctx);

	free(pass);

	/* compare sha256 sum with LOGIN msg trailer */
	if (memcmp(md, cli->msg + (msgsz - SHA256_DIGEST_LENGTH),
		   SHA256_DIGEST_LENGTH)) {
		applog(LOG_WARNING, "invalid password for user %s", user);
		err_code = BC_ERR_AUTH;
		goto err_out;
	}

	/* apply requested configuration options */
	cfg = json_object_get(obj, "config");
	if (json_is_object(cfg) && !cli_config(cli, cfg)) {
		err_code = BC_ERR_CONFIG;
		goto err_out;
	}

	/* build result object, describing server setup */
	res_cfgobj = json_object();
	resobj = json_object();
	if (json_object_set_new(resobj, "version", json_integer(1)) ||
	    json_object_set_new(resobj, "server-name",
	    			json_string(PACKAGE)) ||
	    json_object_set_new(resobj, "server-version",
	    			json_string(VERSION)) ||
	    json_object_set_new(resobj, "config", res_cfgobj)) {
		json_decref(res_cfgobj);
		goto err_out_resobj;
	}

	rc = cli_send_obj(cli, BC_OP_LOGIN_RESP, resobj);

	json_decref(resobj);

	if (rc) {
		strcpy(cli->auth_user, user);
		cli->logged_in = true;
	}

	return rc;

err_out_resobj:
	json_decref(resobj);
err_out:
	cli_send_err(cli, BC_OP_LOGIN_RESP, err_code, bc_err_str[err_code]);
	return false;
}

bool cli_op_config(struct client *cli, const json_t *cfg)
{
	json_t *res;
	bool rc;

	/* apply requested configuration options */
	if (json_is_object(cfg) && !cli_config(cli, cfg)) {
		cli_send_err(cli, BC_OP_CONFIG_RESP, BC_ERR_CONFIG,
			     bc_err_str[BC_ERR_CONFIG]);
		return false;
	}

	/* build result object, describing configuration.
	 * this is the 'config' object returned from
	 * BC_OP_LOGIN_RESP
	 */
	res = json_object();

	rc = cli_send_obj(cli, BC_OP_CONFIG_RESP, res);

	json_decref(res);

	return rc;
}

bool cli_op_work_get(struct client *cli, unsigned int msgsz)
{
	json_t *val;
	int err_code = BC_ERR_INVALID;
	struct ubbp_header *msg_hdr;
	struct bc_work work;
	void *raw_msg;
	size_t msg_len;
	bool rc;

	if (msgsz > 0)
		return false;

	/* obtain work from upstream server */
	val = get_work(cli->auth_user);
	if (!val) {
		err_code = BC_ERR_RPC;
		goto err_out;
	}

	/* decode result into work state struct */
	rc = work_decode(val, &work);

	json_decref(val);

	if (!rc) {
		err_code = BC_ERR_RPC;
		goto err_out;
	}

	/* alloc new message buffer */
	msg_len = sizeof(struct ubbp_header) + sizeof(struct bc_work);

	raw_msg = calloc(1, msg_len);
	if (!raw_msg) {
		err_code = BC_ERR_INTERNAL;
		goto err_out;
	}

	/* build BC_OP_WORK message: hdr + bc_work */
	msg_hdr = raw_msg;
	memcpy(msg_hdr->magic, PUSHPOOL_UBBP_MAGIC, 4);
	msg_hdr->op_size = htole32(UBBP_OP_SIZE(BC_OP_WORK,
						sizeof(struct bc_work)));
	memcpy(raw_msg + sizeof(struct ubbp_header),
	       &work, sizeof(struct bc_work));

	rc = cli_send_msg(cli, raw_msg, msg_len);

	free(raw_msg);

	return rc;

err_out:
	cli_send_err(cli, BC_OP_RESP_ERR, err_code, bc_err_str[err_code]);
	return false;
}

bool cli_op_work_submit(struct client *cli, unsigned int msgsz)
{
	int err_code = BC_ERR_INVALID;
	const char *reason;

	if (msgsz != 128)
		goto err_out;
	if (!submit_bin_work(cli->addr_host, cli->auth_user,
			     srv.curl, cli->msg, &reason)) {
		err_code = BC_ERR_RPC;
		goto err_out;
	}
	if (reason) {
		err_code = BC_ERR_WORK_REJECT;
		goto err_out;
	}

	return cli_send_hdronly(cli, BC_OP_RESP_OK);

err_out:
	cli_send_err(cli, BC_OP_RESP_ERR, err_code, bc_err_str[err_code]);
	return false;
}

static json_t *json_rpc_errobj(int code, const char *msg)
{
	json_t *err;

	err = json_object();
	if (!err)
		return NULL;

	json_object_set_new(err, "code", json_integer(code));
	json_object_set_new(err, "message", json_string(msg));

	return err;
}

bool msg_json_rpc(struct evhttp_request *req, json_t *jreq,
		  const char *username,
		  void **reply, unsigned int *reply_len)
{
	const char *method;
	json_t *params, *id, *resp;
	char *resp_str;
	bool rc = false;
	unsigned int n_params;

	method = json_string_value(json_object_get(jreq, "method"));
	params = json_object_get(jreq, "params");
	n_params = json_array_size(params);
	id = json_object_get(jreq, "id");

	resp = json_object();
	if (!resp)
		return false;
	json_object_set(resp, "id", id);

	if (!method || strcmp(method, "getwork")) {
		json_object_set_new(resp, "result", json_null());
		json_object_set_new(resp, "error",
				    json_rpc_errobj(-1, "method not getwork"));
		goto out;
	}

	/* get new work */
	if (n_params == 0) {
		json_t *val, *result;

		/* obtain work from upstream server */
		val = get_work(username);
		if (!val) {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-2, "upstream RPC error"));
			goto out;
		}

		result = json_object_get(val, "result");
		if (!result) {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-5, "upstrm RPC corrupt"));
			goto out;
		}

		/* use work directly as 'result' in response to client */
		json_object_set_new(resp, "result", json_deep_copy(result));
		json_object_set_new(resp, "error", json_null());

		json_decref(val);
	}

	/* submit solution */
	else {
		json_t *soln;
		const char *soln_str, *reason;
		size_t soln_len;
		bool rpc_rc = false;

		soln = json_array_get(params, 0);
		soln_str = json_string_value(soln);
		soln_len = strlen(soln_str);
		if (!soln_str || soln_len < (80*2) || soln_len > (128*2)) {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-3, "invalid solution"));
			goto out;
		}

		rpc_rc = submit_work(req->remote_host, username, srv.curl,
				     soln_str, &reason);

		if (rpc_rc) {
			json_object_set_new(resp, "result",
				reason ? json_false() : json_true());
			if (reason)
				evhttp_add_header(req->output_headers, "X-Reject-Reason", reason);
			json_object_set_new(resp, "error", json_null());
		} else {
			json_object_set_new(resp, "result", json_null());
			json_object_set_new(resp, "error",
				    json_rpc_errobj(-4, "upstream RPC error"));
		}
	}

out:
	resp_str = json_dumps(resp, JSON_COMPACT);
	if (!resp_str)
		goto out_decref;

	*reply = resp_str;
	*reply_len = strlen(resp_str);

	rc = true;

out_decref:
	json_decref(resp);
	return rc;
}


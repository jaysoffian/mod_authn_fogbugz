/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ap_provider.h>
#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <apr_lib.h>
#include <apr_dbd.h>
#include <mod_dbd.h>
#include <apr_strings.h>
#include <mod_auth.h>
#include <apu_version.h>
#include <util_md5.h>

module AP_MODULE_DECLARE_DATA authn_fogbugz_module;

typedef struct {
    const char *user;
    const char *realm;
} authn_fogbugz_conf;

/* optional function - look it up once in post_config */
static ap_dbd_t *(*authn_fogbugz_acquire_fn)(request_rec*) = NULL;
static void (*authn_fogbugz_prepare_fn)(server_rec*, const char*, const char*) = NULL;

static void *authn_fogbugz_cr_conf(apr_pool_t *pool, char *dummy)
{
    authn_fogbugz_conf *ret = apr_pcalloc(pool, sizeof(authn_fogbugz_conf));
    return ret;
}
static void *authn_fogbugz_merge_conf(apr_pool_t *pool, void *BASE, void *ADD)
{
    authn_fogbugz_conf *add = ADD;
    authn_fogbugz_conf *base = BASE;
    authn_fogbugz_conf *ret = apr_palloc(pool, sizeof(authn_fogbugz_conf));
    ret->user = (add->user == NULL) ? base->user : add->user;
    ret->realm = (add->realm == NULL) ? base->realm : add->realm;
    return ret;
}
static const char *authn_fogbugz_prepare(cmd_parms *cmd, void *cfg, const char *query)
{
    static unsigned int label_num = 0;
    char *label;

    if (authn_fogbugz_prepare_fn == NULL) {
        authn_fogbugz_prepare_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_prepare);
        if (authn_fogbugz_prepare_fn == NULL) {
            return "You must load mod_dbd to enable AuthFogBugz functions";
        }
        authn_fogbugz_acquire_fn = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
    }
    label = apr_psprintf(cmd->pool, "authn_fogbugz_%d", ++label_num);

    authn_fogbugz_prepare_fn(cmd->server, query, label);

    /* save the label here for our own use */
    return ap_set_string_slot(cmd, cfg, label);
}
static const command_rec authn_fogbugz_cmds[] =
{
    AP_INIT_TAKE1("AuthFogBugzUserPWQuery", authn_fogbugz_prepare,
                  (void *) APR_OFFSETOF(authn_fogbugz_conf, user), ACCESS_CONF,
                  "Query used to fetch password for user"),
    AP_INIT_TAKE1("AuthFogBugzUserRealmQuery", authn_fogbugz_prepare,
                  (void *) APR_OFFSETOF(authn_fogbugz_conf, realm), ACCESS_CONF,
                  "Query used to fetch password for user+realm"),
    {NULL}
};
static apr_status_t validate_password(request_rec* r, const char* password,
                                      const char* hash)
{
    int hash_len = strlen(hash);
    if (hash_len != 40) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid hashed password length, %d", hash_len);
        return AUTH_GENERAL_ERROR;
    }
    char *salt = apr_pstrndup(r->pool, hash, 8);
    char *salted_pw = apr_pstrcat(r->pool, password, salt, NULL);
    char *hexdigest = ap_md5(r->pool, (unsigned char *) salted_pw);
    char *sample = apr_pstrcat(r->pool, salt, hexdigest, NULL);
    return (strcmp(sample, hash) == 0) ? APR_SUCCESS : APR_EMISMATCH;
}
static authn_status authn_fogbugz_password(request_rec *r, const char *user,
                                           const char *password)
{
    apr_status_t rv;
    const char *dbd_password = NULL;
    apr_dbd_prepared_t *statement;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;

    authn_fogbugz_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &authn_fogbugz_module);
    ap_dbd_t *dbd = authn_fogbugz_acquire_fn(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to acquire database connection to look up "
                      "user '%s'", user);
        return AUTH_GENERAL_ERROR;
    }

    if (conf->user == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "No AuthFogBugzUserPWQuery has been specified");
        return AUTH_GENERAL_ERROR;
    }

    statement = apr_hash_get(dbd->prepared, conf->user, APR_HASH_KEY_STRING);
    if (statement == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "A prepared statement could not be found for "
                      "AuthFogBugzUserPWQuery with the key '%s'", conf->user);
        return AUTH_GENERAL_ERROR;
    }
    if (apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res, statement,
                              0, user, NULL) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Query execution error looking up '%s' "
                      "in database", user);
        return AUTH_GENERAL_ERROR;
    }
    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Error retrieving results while looking up '%s' "
                          "in database", user);
            return AUTH_GENERAL_ERROR;
        }
        if (dbd_password == NULL) {
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 3)
            /* add the rest of the columns to the environment */
            int i = 1;
            const char *name;
            for (name = apr_dbd_get_name(dbd->driver, res, i);
                 name != NULL;
                 name = apr_dbd_get_name(dbd->driver, res, i)) {

                char *str = apr_pstrcat(r->pool, AUTHN_PREFIX,
                                        name,
                                        NULL);
                int j = sizeof(AUTHN_PREFIX)-1; /* string length of "AUTHENTICATE_", excluding the trailing NIL */
                while (str[j]) {
                    if (!apr_isalnum(str[j])) {
                        str[j] = '_';
                    }
                    else {
                        str[j] = apr_toupper(str[j]);
                    }
                    j++;
                }
                apr_table_set(r->subprocess_env, str,
                              apr_dbd_get_entry(dbd->driver, row, i));
                i++;
            }
#endif
            dbd_password = apr_dbd_get_entry(dbd->driver, row, 0);
        }
        /* we can't break out here or row won't get cleaned up */
    }

    if (!dbd_password) {
        return AUTH_USER_NOT_FOUND;
    }

    rv = validate_password(r, password, dbd_password);

    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}
static authn_status authn_fogbugz_realm(request_rec *r, const char *user,
                                    const char *realm, char **rethash)
{
    apr_status_t rv;
    const char *dbd_hash = NULL;
    apr_dbd_prepared_t *statement;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;

    authn_fogbugz_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &authn_fogbugz_module);
    ap_dbd_t *dbd = authn_fogbugz_acquire_fn(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to acquire database connection to look up "
                      "user '%s:%s'", user, realm);
        return AUTH_GENERAL_ERROR;
    }
    if (conf->realm == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "No AuthFogBugzUserRealmQuery has been specified");
        return AUTH_GENERAL_ERROR;
    }
    statement = apr_hash_get(dbd->prepared, conf->realm, APR_HASH_KEY_STRING);
    if (statement == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "A prepared statement could not be found for "
                      "AuthFogBugzUserRealmQuery with the key '%s'", conf->realm);
    }
    if (apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res, statement,
                              0, user, realm, NULL) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Query execution error looking up '%s:%s' "
                      "in database", user, realm);
        return AUTH_GENERAL_ERROR;
    }
    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Error retrieving results while looking up '%s:%s' "
                          "in database", user, realm);
            return AUTH_GENERAL_ERROR;
        }
        if (dbd_hash == NULL) {
#if APU_MAJOR_VERSION > 1 || (APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 3)
            /* add the rest of the columns to the environment */
            int i = 1;
            const char *name;
            for (name = apr_dbd_get_name(dbd->driver, res, i);
                 name != NULL;
                 name = apr_dbd_get_name(dbd->driver, res, i)) {

                char *str = apr_pstrcat(r->pool, AUTHN_PREFIX,
                                        name,
                                        NULL);
                int j = sizeof(AUTHN_PREFIX)-1; /* string length of "AUTHENTICATE_", excluding the trailing NIL */
                while (str[j]) {
                    if (!apr_isalnum(str[j])) {
                        str[j] = '_';
                    }
                    else {
                        str[j] = apr_toupper(str[j]);
                    }
                    j++;
                }
                apr_table_set(r->subprocess_env, str,
                              apr_dbd_get_entry(dbd->driver, row, i));
                i++;
            }
#endif
            dbd_hash = apr_dbd_get_entry(dbd->driver, row, 0);
        }
        /* we can't break out here or row won't get cleaned up */
    }

    if (!dbd_hash) {
        return AUTH_USER_NOT_FOUND;
    }

    *rethash = apr_pstrdup(r->pool, dbd_hash);
    return AUTH_USER_FOUND;
}
static void authn_fogbugz_register_hooks(apr_pool_t *p)
{
    static const authn_provider authn_fogbugz_provider = {
        &authn_fogbugz_password,
        &authn_fogbugz_realm
    };

    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "fogbugz", "0", &authn_fogbugz_provider);
}
module AP_MODULE_DECLARE_DATA authn_fogbugz_module =
{
    STANDARD20_MODULE_STUFF,
    authn_fogbugz_cr_conf,
    authn_fogbugz_merge_conf,
    NULL,
    NULL,
    authn_fogbugz_cmds,
    authn_fogbugz_register_hooks
};

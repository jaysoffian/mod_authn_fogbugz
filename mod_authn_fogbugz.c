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
static APR_OPTIONAL_FN_TYPE(ap_dbd_acquire) *authn_fogbugz_acquire;

typedef struct {
    const char *label;
} authn_fogbugz_conf;

static void *create_authn_fogbugz_dir_config(apr_pool_t *p, char *dummy)
{
    authn_fogbugz_conf *conf = apr_palloc(p, sizeof(*conf));
    conf->label = "fogbugz";
    return conf;
}

static const char *set_authn_label_slot(cmd_parms *cmd, void *offset,
                                        const char *label)
{
    return ap_set_string_slot(cmd, offset, label);
};

static const command_rec authn_fogbugz_cmds[] =
{
    AP_INIT_TAKE1("AuthFogBugzQueryLabel", set_authn_label_slot,
                  (void *)APR_OFFSETOF(authn_fogbugz_conf, label),
                  ACCESS_CONF,
                  "Label of the SQL statement prepared via the DBDPrepareSQL "
                  "directive (defaults to 'fogbugz') used to query "
                  "authentication details."),
    {NULL}
};

static const char *encrypt_password_600(request_rec* r,
                                        const char* cleartext,
                                        const char* salt)
{
    const char *salted = apr_pstrcat(r->pool, cleartext, salt, NULL);
    const char *hashed = ap_md5(r->pool, (unsigned char *) salted);
    return apr_pstrcat(r->pool, salt, hashed, NULL);
}

static const char *encrypt_password_840(request_rec* r,
                                        const char* cleartext,
                                        const char* salt)
{
    int outer = 100, inner;
    char hash[4000]; /* large enough for 100 iterations of md5 hexdigest */
    char *cp;
    apr_pool_t *sp;
    apr_pool_create(&sp, r->pool);
    /* sHash = MD5Hash(sPassword & sSalt) */
    strcpy(hash, ap_md5(sp, (unsigned char *)
        apr_pstrcat(sp, cleartext, salt, NULL)));
    cp = hash + 32;
    while (outer-- > 0) {
        apr_pool_clear(sp);
        inner = outer;
        while (inner-- > 0) {
            /* sHash = sHash & MD5Hash(sHash & sPassword & sSalt) */
            strcpy(cp, ap_md5(sp, (unsigned char *)
                apr_pstrcat(sp, hash, cleartext, salt, NULL)));
            cp += 32;
            apr_pool_clear(sp);
        }
        /* sHash = MD5Hash(sHash) */
        strcpy(hash, ap_md5(sp, (unsigned char *) hash));
        cp = hash + 32;
    }
    apr_pool_destroy(sp);
    /* sHash = sSalt & MD5Hash(sHash) */
    return apr_pstrcat(r->pool,
        salt, ap_md5(r->pool, (unsigned char *) hash), NULL);
}

static apr_status_t compare_passwords(request_rec* r,
                                      const char* cleartext,
                                      const char* encrypted,
                                      const char* pwversion)
{
    const char *sample = NULL;
    const char *salt = NULL;
    int encrypted_len = strlen(encrypted);
    if (encrypted_len != 40) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Invalid encrypted password length, %d", encrypted_len);
        return AUTH_GENERAL_ERROR;
    }
    salt = apr_pstrndup(r->pool, encrypted, 8);
    if (strcmp(pwversion, "600") == 0) {
        sample = encrypt_password_600(r, cleartext, salt);
    } else if (strcmp(pwversion, "840") == 0) {
        sample = encrypt_password_840(r, cleartext, salt);
    } else {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Unsupported sPasswordVersion, %s", pwversion);
        return AUTH_GENERAL_ERROR;
    }
    return (strcmp(sample, encrypted) == 0) ? APR_SUCCESS : APR_EMISMATCH;
}

static authn_status authn_fogbugz_check_password(request_rec *r,
                                                 const char *username,
                                                 const char *password)
{
    apr_status_t rv;
    const char *encrypted = NULL;
    const char *pwversion = NULL;
    apr_dbd_prepared_t *statement;
    apr_dbd_results_t *res = NULL;
    apr_dbd_row_t *row = NULL;

    authn_fogbugz_conf *conf = ap_get_module_config(r->per_dir_config,
                                                    &authn_fogbugz_module);
    ap_dbd_t *dbd = authn_fogbugz_acquire(r);
    if (dbd == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Failed to acquire database connection to look up "
                      "user '%s'", username);
        return AUTH_GENERAL_ERROR;
    }

    statement = apr_hash_get(dbd->prepared, conf->label, APR_HASH_KEY_STRING);
    if (statement == NULL) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "A prepared statement with the key '%s' could not be "
                      "found", conf->label);
        return AUTH_GENERAL_ERROR;
    }
    if (apr_dbd_pvselect(dbd->driver, r->pool, dbd->handle, &res, statement,
                              0, username, NULL) != 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Query execution error looking up '%s' "
                      "in database", username);
        return AUTH_GENERAL_ERROR;
    }
    for (rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1);
         rv != -1;
         rv = apr_dbd_get_row(dbd->driver, r->pool, res, &row, -1)) {
        if (rv != 0) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                          "Error retrieving results while looking up '%s' "
                          "in database", username);
            return AUTH_GENERAL_ERROR;
        }
        if (encrypted == NULL) {
            encrypted = apr_dbd_get_entry(dbd->driver, row, 0);
            pwversion = apr_dbd_get_entry(dbd->driver, row, 1);

        }
        /* we can't break out here or row won't get cleaned up */
    }

    if (!encrypted) {
        return AUTH_USER_NOT_FOUND;
    }

    rv = compare_passwords(r, password, encrypted, pwversion);
    if (rv != APR_SUCCESS) {
        return AUTH_DENIED;
    }

    return AUTH_GRANTED;
}

static const authn_provider authn_fogbugz_provider =
{
    &authn_fogbugz_check_password,
};

static void ImportDBDOptFn(void)
{
    authn_fogbugz_acquire = APR_RETRIEVE_OPTIONAL_FN(ap_dbd_acquire);
}

static void register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, "fogbugz", "0",
                         &authn_fogbugz_provider);
    ap_hook_optional_fn_retrieve(ImportDBDOptFn, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA authn_fogbugz_module =
{
    STANDARD20_MODULE_STUFF,
    create_authn_fogbugz_dir_config, /* dir config creater */
    NULL,                            /* dir merger --- default is to override */
    NULL,                            /* server config */
    NULL,                            /* merge server config */
    authn_fogbugz_cmds,              /* command apr_table_t */
    register_hooks                   /* register hooks */
};

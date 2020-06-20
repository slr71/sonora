/**
 * Application authentication module.
 *
 * @module auth
 */

import path from "path";
import qs from "qs";

import session from "express-session";
import pgsimple from "connect-pg-simple";
import keycloak from "keycloak-connect";

import axiosInstance from "../common/getAxios";

import * as config from "./configuration";

const IMPERSONATION_TOKEN_KEY = "impersonation-token";

/**
 * Stores the impersonation token from the request session in the request
 * object if it's present.
 *
 * @param {Object} req
 */
export const impersonationMiddleware = (req, res, next) => {
    if (req.session[IMPERSONATION_TOKEN_KEY]) {
        req.iauth.grant = req.session[IMPERSONATION_TOKEN_KEY];
    }
    next(req, res);
};

/**
 * Obtains the user's actual access token from the request.
 * @param {Object} req
 */
export const getActualToken = (req) => {
    return req?.kauth?.grant?.access_token;
};

/**
 * Obtains the access token that is currently in effect if any are in effect.
 * Some administrators have the ability to impersonate other users for
 * troubleshooting purposes. If impersonation is in effect then the effective
 * token is the one that was obtained in order to impersonate another user.
 * Otherwise, the effective token is the user's actual token. If the user is
 * not logged in at all then a null value will be returned.
 *
 * @param {Object} req
 */
export const getEffectiveToken = (req) => {
    return req?.iauth?.grant?.access_token || getActualToken(req);
};

/**
 * Extracts the username from the calims in the JWT access token.
 *
 * @param {Object} req
 */
export const getUserID = (req) => {
    return getEffectiveToken(req)?.content?.preferred_username;
};

/**
 * Attempts to obtain an impersonation token for the authenticated user. The
 * user (obviously) must be logged in for this to work, but This function makes
 * no attempt to verify that this is the case. Instead, the calling handler
 * must ensure that the user is logged in. The impersonation token will only be
 * granted if the user has impersonation privileges in Keycloak.
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 * @param {String} username
 */
export const impersonate = (req, res, next, username) => {
    // Build the URL for the token exchange.
    const url = new URL(config.keycloakServerURL);
    url.pathname = path.join(
        url.pathname,
        "realms",
        config.keycloakRealm,
        "protocol",
        "openid-connect",
        "token"
    );

    // Build the request body.
    const data = {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        client_id: config.keycloakClientID,
        client_secret: config.keycloakClientSecret,
        subject_token: getActualToken(),
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        requested_subject: username,
    };

    // Send the request.
    return axiosInstance
        .post(url.toString(), qs.stringify(data))
        .then((response) => {
            console.log(response.data);
            req.session[IMPERSONATION_TOKEN_KEY] = response.data;
        })
        .then(next(req, res))
        .catch(() => next(req, res));
};

/**
 * Stops impersonation.
 * @param {Object} req
 * @param {Object} res
 * @param {Function} next
 */
export const stopImpersonation = (req, res, next) => {
    delete req.session[IMPERSONATION_TOKEN_KEY];
    next(req, res);
};

/**
 * Extracts the user profile from the claims in the JWT access token.
 *
 * @param {Object} req
 */
export const getUserProfile = (req) => {
    const accessToken = getEffectiveToken(req);
    if (accessToken) {
        return {
            id: accessToken.content.preferred_username,
            attributes: {
                email: accessToken.content.email,
                entitlement: accessToken.content.entitlement,
                firstName: accessToken.content.given_name,
                lastName: accessToken.content.family_name,
                name: accessToken.content.name,
            },
        };
    } else {
        return null;
    }
};

/**
 * Adds the access token to the Authorization header if it's present in the request.
 */
export const authnTokenMiddleware = (req, res, next) => {
    const token = getEffectiveToken(req).token;

    if (token) {
        req.headers["Authorization"] = `Bearer ${token}`;
    }

    next();
};

// Configure the session store.
const pgSession = pgsimple(session);
let sessionStore;

/**
 * Returns the session store instance for the application.
 *
 * @returns {Object}
 */
const getSessionStore = () => {
    if (!sessionStore) {
        sessionStore = new pgSession({
            conString: config.dbURI,
            tableName: "session",
            ttl: config.sessionTTL,
        });
    }
    return sessionStore;
};

/**
 * Returns Express middleware for session management.
 *
 * @returns {Object}
 */
export const sessionMiddleware = () =>
    session({
        store: getSessionStore(),
        secret: config.sessionSecret,
        resave: false,
        saveUninitialized: true,
        cookie: {
            secure: config.sessionSecureCookie,
        },
    });

let keycloakClient;

/**
 * Returns a newly instantiated Keycloak client.
 *
 * @returns {Object}
 */
export const getKeycloakClient = () => {
    if (!keycloakClient) {
        keycloakClient = new keycloak(
            {
                store: getSessionStore(),
            },
            {
                serverUrl: config.keycloakServerURL,
                realm: config.keycloakRealm,
                clientId: config.keycloakClientID,
                secret: config.keycloakClientSecret,
            }
        );
    }

    return keycloakClient;
};

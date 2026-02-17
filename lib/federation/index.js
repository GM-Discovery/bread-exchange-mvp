"use strict";

const { installFederationRouter } = require("./routes");

/**
 * Federation module public API.
 * Only export installFederationRoutes to prevent export drift.
 */
function installFederationRoutes(app) {
  try {
    installFederationRouter(app);
  } catch (e) {
    console.error("FEDERATION_ROUTES_INSTALL_FAILED:", e && e.message ? e.message : e);
  }
}

module.exports = {
  installFederationRoutes,
};

// ============================================================
// NAIRA MASTER — HGT BACKEND
// Node.js + Express + Firebase Admin + Squad
// ============================================================

require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");

// ------------------------------------------------------------
// ENVIRONMENT
// ------------------------------------------------------------

const PORT = Number(process.env.PORT || 10000);
const NODE_ENV = process.env.NODE_ENV || "development";

const FRONTEND_URL = (
  process.env.FRONTEND_URL || ""
).replace(/\/+$/, "");

const CORS_ORIGINS = (
  process.env.CORS_ORIGINS ||
  FRONTEND_URL
)
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

// Squad
const SQUAD_BASE_URL = (
  process.env.SQUAD_BASE_URL ||
  "https://sandbox-api-d.squadco.com"
).replace(/\/+$/, "");

const SQUAD_SECRET_KEY =
  process.env.SQUAD_SECRET_KEY || "";

const SQUAD_WEBHOOK_SECRET =
  process.env.SQUAD_WEBHOOK_SECRET ||
  SQUAD_SECRET_KEY;

const SQUAD_CALLBACK_URL =
  process.env.SQUAD_CALLBACK_URL ||
  `${FRONTEND_URL}/payment-callback`;

// Firebase
const FIREBASE_PROJECT_ID =
  process.env.FIREBASE_PROJECT_ID || "";

const FIREBASE_CLIENT_EMAIL =
  process.env.FIREBASE_CLIENT_EMAIL || "";

const FIREBASE_PRIVATE_KEY =
  process.env.FIREBASE_PRIVATE_KEY || "";

const FIREBASE_PRIVATE_KEY_BASE64 =
  process.env.FIREBASE_PRIVATE_KEY_BASE64 || "";

// Naira Master rules
const MIN_WALLET_FUNDING_NAIRA = Number(
  process.env.MIN_WALLET_FUNDING_NAIRA || 100
);

const TASK_CREATION_FEE_NAIRA = Number(
  process.env.TASK_CREATION_FEE_NAIRA || 1000
);

const PAYMENT_EXPIRY_MINUTES = Number(
  process.env.PAYMENT_EXPIRY_MINUTES || 60
);

// ------------------------------------------------------------
// REQUIRED ENVIRONMENT CHECK
// ------------------------------------------------------------

function requireEnv(name, value) {
  if (!value) {
    throw new Error(
      `Missing required environment variable: ${name}`
    );
  }
}

requireEnv("FIREBASE_PROJECT_ID", FIREBASE_PROJECT_ID);
requireEnv("FIREBASE_CLIENT_EMAIL", FIREBASE_CLIENT_EMAIL);
requireEnv("SQUAD_SECRET_KEY", SQUAD_SECRET_KEY);

if (
  !FIREBASE_PRIVATE_KEY &&
  !FIREBASE_PRIVATE_KEY_BASE64
) {
  throw new Error(
    "Missing FIREBASE_PRIVATE_KEY or FIREBASE_PRIVATE_KEY_BASE64"
  );
}

// ------------------------------------------------------------
// FIREBASE PRIVATE KEY
// ------------------------------------------------------------

function getFirebasePrivateKey() {
  // Option 1:
  // FIREBASE_PRIVATE_KEY_BASE64
  if (FIREBASE_PRIVATE_KEY_BASE64) {
    try {
      return Buffer
        .from(
          FIREBASE_PRIVATE_KEY_BASE64,
          "base64"
        )
        .toString("utf8")
        .trim();
    } catch (error) {
      throw new Error(
        "FIREBASE_PRIVATE_KEY_BASE64 could not be decoded"
      );
    }
  }

  // Option 2:
  // FIREBASE_PRIVATE_KEY containing \n
  return FIREBASE_PRIVATE_KEY
    .replace(/\\n/g, "\n")
    .replace(/\r\n/g, "\n")
    .trim();
}

const firebasePrivateKey =
  getFirebasePrivateKey();

// Basic validation so Render fails immediately
// rather than producing confusing Firebase errors.
if (
  !firebasePrivateKey.includes(
    "-----BEGIN PRIVATE KEY-----"
  ) ||
  !firebasePrivateKey.includes(
    "-----END PRIVATE KEY-----"
  )
) {
  throw new Error(
    "FIREBASE_PRIVATE_KEY does not appear to contain a valid PEM private key"
  );
}

// ------------------------------------------------------------
// FIREBASE ADMIN INITIALIZATION
// ------------------------------------------------------------

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: firebasePrivateKey
    })
  });
}

const db = admin.firestore();
const auth = admin.auth();

const FieldValue =
  admin.firestore.FieldValue;

// ------------------------------------------------------------
// EXPRESS
// ------------------------------------------------------------

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);

// ------------------------------------------------------------
// CORS
// ------------------------------------------------------------

app.use(
  cors({
    origin(origin, callback) {

      // Allow server-to-server requests
      if (!origin) {
        return callback(null, true);
      }

      // If no CORS list has been configured,
      // do not allow arbitrary browser origins.
      if (
        CORS_ORIGINS.length === 0
      ) {
        return callback(
          new Error("CORS_ORIGINS is not configured")
        );
      }

      if (
        CORS_ORIGINS.includes(origin)
      ) {
        return callback(null, true);
      }

      return callback(
        new Error("CORS origin not allowed")
      );
    },

    credentials: true
  })
);

// ------------------------------------------------------------
// JSON BODY
//
// IMPORTANT:
// The Squad webhook route below is mounted BEFORE this parser,
// because webhook signature verification needs the raw body.
// ------------------------------------------------------------

// ------------------------------------------------------------
// UTILITY FUNCTIONS
// ------------------------------------------------------------

function nairaToKobo(amount) {
  const value = Number(amount);

  if (
    !Number.isFinite(value) ||
    value <= 0
  ) {
    throw new Error("Invalid amount");
  }

  return Math.round(value * 100);
}

function koboToNaira(amount) {
  return Number(amount) / 100;
}

function createReference(prefix) {
  return (
    `${prefix}-` +
    `${Date.now()}-` +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );
}

function safeString(value) {
  if (
    value === undefined ||
    value === null
  ) {
    return "";
  }

  return String(value);
}

function normalizeStatus(status) {
  return safeString(status)
    .trim()
    .toLowerCase();
}

// ------------------------------------------------------------
// FIREBASE AUTHENTICATION
// ------------------------------------------------------------

async function authenticateFirebase(
  req,
  res,
  next
) {
  try {

    const authorization =
      req.headers.authorization || "";

    if (
      !authorization.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Firebase authentication token is required"
      });
    }

    const idToken =
      authorization
        .substring(7)
        .trim();

    if (!idToken) {
      return res.status(401).json({
        success: false,
        message:
          "Firebase authentication token is empty"
      });
    }

    const decoded =
      await auth.verifyIdToken(idToken);

    req.user = decoded;

    next();

  } catch (error) {

    console.error(
      "Firebase authentication error:",
      error.message
    );

    return res.status(401).json({
      success: false,
      message:
        "Invalid or expired Firebase authentication token"
    });
  }
}

// ------------------------------------------------------------
// SQUAD HTTP CLIENT
// ------------------------------------------------------------

async function squadRequest(
  endpoint,
  options = {}
) {

  const response = await fetch(
    `${SQUAD_BASE_URL}${endpoint}`,
    {
      method:
        options.method || "GET",

      headers: {
        "Authorization":
          `Bearer ${SQUAD_SECRET_KEY}`,

        "Content-Type":
          "application/json",

        ...(options.headers || {})
      },

      body:
        options.body
    }
  );

  const text =
    await response.text();

  let data = {};

  try {
    data =
      text
        ? JSON.parse(text)
        : {};
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {

    const error =
      new Error(
        data?.message ||
        `Squad request failed with HTTP ${response.status}`
      );

    error.status =
      response.status;

    error.squad =
      data;

    throw error;
  }

  return data;
}

// ------------------------------------------------------------
// SQUAD TRANSACTION VERIFICATION
// ------------------------------------------------------------

async function verifySquadTransaction(
  transactionReference
) {

  /*
   * Squad's verification endpoint is called
   * with the transaction reference.
   *
   * Keep this function isolated so if Squad
   * changes the verification route in its API,
   * only this function needs changing.
   */

  return squadRequest(
    `/transaction/verify/${encodeURIComponent(
      transactionReference
    )}`,
    {
      method: "GET"
    }
  );
}

// ------------------------------------------------------------
// SQUAD WEBHOOK SIGNATURE
// ------------------------------------------------------------

function compareSignature(
  expected,
  received
) {

  if (
    !expected ||
    !received
  ) {
    return false;
  }

  const expectedBuffer =
    Buffer.from(
      String(expected).trim(),
      "utf8"
    );

  const receivedBuffer =
    Buffer.from(
      String(received).trim(),
      "utf8"
    );

  if (
    expectedBuffer.length !==
    receivedBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    expectedBuffer,
    receivedBuffer
  );
}

function validateSquadWebhook(
  rawBody,
  parsedBody,
  signature
) {

  if (
    !signature ||
    !SQUAD_WEBHOOK_SECRET
  ) {
    return false;
  }

  /*
   * Squad's documented webhook validation
   * uses HMAC SHA-512.
   */

  // Version based on the actual raw request body.
  const rawHash =
    crypto
      .createHmac(
        "sha512",
        SQUAD_WEBHOOK_SECRET
      )
      .update(rawBody)
      .digest("hex");

  if (
    compareSignature(
      rawHash,
      signature
    )
  ) {
    return true;
  }

  /*
   * Squad's Node example hashes:
   * JSON.stringify(req.body)
   *
   * We also calculate that form for compatibility.
   */

  const normalizedBody =
    JSON.stringify(parsedBody);

  const normalizedHash =
    crypto
      .createHmac(
        "sha512",
        SQUAD_WEBHOOK_SECRET
      )
      .update(normalizedBody)
      .digest("hex");

  return compareSignature(
    normalizedHash,
    signature
  );
}

// ------------------------------------------------------------
// PAYMENT RECORD
// ------------------------------------------------------------

async function createPaymentRecord({
  uid,
  email,
  customerName,
  purpose,
  amountNaira,
  transactionReference
}) {

  const ref =
    db
      .collection("paymentRecords")
      .doc(transactionReference);

  const createdAt =
    FieldValue.serverTimestamp();

  await ref.create({

    transactionReference,

    uid,

    email:
      email || null,

    customerName:
      customerName || null,

    purpose,

    amountNaira,

    amountKobo:
      nairaToKobo(amountNaira),

    currency:
      "NGN",

    status:
      "pending",

    credited:
      false,

    createdAt,

    updatedAt:
      createdAt,

    expiresAt:
      admin.firestore.Timestamp.fromMillis(
        Date.now() +
        PAYMENT_EXPIRY_MINUTES *
        60 *
        1000
      )

  });

  return ref;
}

// ------------------------------------------------------------
// EXTRACT SQUAD TRANSACTION
// ------------------------------------------------------------

function extractSquadTransaction(
  payload
) {

  const body =
    payload?.Body ||
    payload?.body ||
    payload?.data ||
    {};

  const transactionReference =
    body.transaction_ref ||
    body.transaction_reference ||
    payload.TransactionRef ||
    payload.transaction_ref ||
    payload.transaction_reference ||
    null;

  const status =
    body.transaction_status ||
    body.status ||
    payload.transaction_status ||
    payload.status ||
    null;

  const amount =
    body.amount ??
    body.transaction_amount ??
    payload.amount ??
    payload.transaction_amount ??
    null;

  const currency =
    body.currency ||
    body.transaction_currency_id ||
    payload.currency ||
    "NGN";

  const metadata =
    body.meta ||
    body.metadata ||
    payload.meta ||
    payload.metadata ||
    {};

  return {

    transactionReference:
      transactionReference
        ? String(transactionReference)
        : null,

    status:
      status
        ? String(status)
        : null,

    amountKobo:
      Number(amount),

    currency:
      String(currency)
        .toUpperCase(),

    email:
      body.email ||
      payload.email ||
      null,

    metadata,

    raw:
      payload
  };
}

// ------------------------------------------------------------
// SUCCESS STATUS
// ------------------------------------------------------------

function isSuccessfulPayment(
  status
) {

  return [
    "success",
    "successful",
    "processed",
    "completed"
  ].includes(
    normalizeStatus(status)
  );
}

// ------------------------------------------------------------
// FAILED STATUS
// ------------------------------------------------------------

function isFailedPayment(
  status
) {

  return [
    "failed",
    "declined",
    "cancelled",
    "canceled",
    "abandoned",
    "rejected"
  ].includes(
    normalizeStatus(status)
  );
}

// ------------------------------------------------------------
// SETTLE WALLET PAYMENT
//
// THIS IS THE MOST IMPORTANT DATABASE FUNCTION.
//
// It uses a Firestore transaction so that:
// - duplicate webhooks cannot double-credit
// - two requests cannot race each other
// - wallet and transaction record stay consistent
// ------------------------------------------------------------

async function settleWalletPayment({
  transactionReference,
  squadTransaction
}) {

  const paymentRef =
    db
      .collection("paymentRecords")
      .doc(transactionReference);

  return db.runTransaction(
    async transaction => {

      const paymentSnapshot =
        await transaction.get(
          paymentRef
        );

      if (
        !paymentSnapshot.exists
      ) {
        throw new Error(
          "Payment record does not exist"
        );
      }

      const payment =
        paymentSnapshot.data();

      // ------------------------------------------------------
      // IDEMPOTENCY
      // ------------------------------------------------------

      if (
        payment.credited === true ||
        payment.status === "credited"
      ) {

        return {
          alreadyCredited: true,
          uid: payment.uid,
          amountNaira:
            payment.amountNaira
        };
      }

      // ------------------------------------------------------
      // AMOUNT CHECK
      // ------------------------------------------------------

      const expectedAmountKobo =
        Number(
          payment.amountKobo
        );

      const actualAmountKobo =
        Number(
          squadTransaction.amountKobo
        );

      if (
        !Number.isFinite(
          actualAmountKobo
        )
      ) {
        throw new Error(
          "Squad returned an invalid amount"
        );
      }

      if (
        actualAmountKobo !==
        expectedAmountKobo
      ) {
        throw new Error(
          "Squad amount does not match payment amount"
        );
      }

      // ------------------------------------------------------
      // CURRENCY CHECK
      // ------------------------------------------------------

      if (
        squadTransaction.currency !==
        "NGN"
      ) {
        throw new Error(
          "Only NGN payments can fund the Naira wallet"
        );
      }

      // ------------------------------------------------------
      // USER
      // ------------------------------------------------------

      const userRef =
        db
          .collection("users")
          .doc(payment.uid);

      const userSnapshot =
        await transaction.get(
          userRef
        );

      if (
        !userSnapshot.exists
      ) {
        throw new Error(
          "Naira Master user does not exist"
        );
      }

      const user =
        userSnapshot.data();

      // ------------------------------------------------------
      // BALANCE
      // ------------------------------------------------------

      const oldBalance =
        Number(
          user.balance || 0
        );

      const amountNaira =
        Number(
          payment.amountNaira
        );

      const newBalance =
        oldBalance +
        amountNaira;

      // ------------------------------------------------------
      // UPDATE USER
      // ------------------------------------------------------

      transaction.update(
        userRef,
        {
          balance:
            newBalance,

          updatedAt:
            FieldValue.serverTimestamp()
        }
      );

      // ------------------------------------------------------
      // TRANSACTION HISTORY
      // ------------------------------------------------------

      const transactionRef =
        db
          .collection("transactions")
          .doc(transactionReference);

      transaction.set(
        transactionRef,
        {

          uid:
            payment.uid,

          type:
            "credit",

          category:
            "wallet_funding",

          purpose:
            payment.purpose,

          amount:
            amountNaira,

          amountKobo:
            expectedAmountKobo,

          currency:
            "NGN",

          reference:
            transactionReference,

          squadReference:
            transactionReference,

          status:
            "Successful",

          balanceBefore:
            oldBalance,

          balanceAfter:
            newBalance,

          name:
            user.name ||
            user.displayName ||
            payment.customerName ||
            null,

          email:
            user.email ||
            payment.email ||
            null,

          source:
            "Squad",

          createdAt:
            FieldValue.serverTimestamp()
        }
      );

      // ------------------------------------------------------
      // MARK PAYMENT AS CREDITED
      // ------------------------------------------------------

      transaction.update(
        paymentRef,
        {

          status:
            "credited",

          credited:
            true,

          creditedAt:
            FieldValue.serverTimestamp(),

          updatedAt:
            FieldValue.serverTimestamp(),

          squadStatus:
            "Success"
        }
      );

      // ------------------------------------------------------
      // NOTIFICATION
      // ------------------------------------------------------

      const notificationRef =
        db
          .collection("notifications")
          .doc();

      transaction.set(
        notificationRef,
        {

          uid:
            payment.uid,

          type:
            "payment",

          title:
            "Payment Successful",

          message:
            `₦${amountNaira.toLocaleString(
              "en-NG"
            )} has been added to your wallet.`,

          amount:
            amountNaira,

          transactionRef:
            transactionReference,

          status:
            "Successful",

          read:
            false,

          createdAt:
            FieldValue.serverTimestamp()
        }
      );

      return {

        alreadyCredited:
          false,

        uid:
          payment.uid,

        amountNaira,

        newBalance
      };
    }
  );
}

// ------------------------------------------------------------
// JSON PARSER
//
// This MUST come AFTER the raw Squad webhook route.
// ------------------------------------------------------------

// ------------------------------------------------------------
// SQUAD WEBHOOK
// ------------------------------------------------------------

app.post(
  "/api/squad/webhook",

  express.raw({
    type:
      "application/json",

    limit:
      "1mb"
  }),

  async (req, res) => {

    const rawBody =
      Buffer.isBuffer(req.body)
        ? req.body
        : Buffer.from(
            req.body || ""
          );

    const signature =
      req.headers[
        "x-squad-signature"
      ];

    let payload;

    try {

      payload =
        JSON.parse(
          rawBody.toString(
            "utf8"
          )
        );

    } catch {

      return res.status(400).json({
        response_code: 400,
        response_description:
          "Invalid JSON"
      });
    }

    // --------------------------------------------------------
    // SIGNATURE
    // --------------------------------------------------------

    const validSignature =
      validateSquadWebhook(
        rawBody,
        payload,
        signature
      );

    if (!validSignature) {

      console.warn(
        "Rejected Squad webhook: invalid signature"
      );

      return res.status(401).json({
        response_code: 400,
        response_description:
          "Invalid webhook signature"
      });
    }

    // --------------------------------------------------------
    // EXTRACT PAYMENT
    // --------------------------------------------------------

    const squad =
      extractSquadTransaction(
        payload
      );

    const transactionReference =
      squad.transactionReference;

    if (!transactionReference) {

      return res.status(400).json({
        response_code: 400,
        response_description:
          "Missing transaction reference"
      });
    }

    try {

      // ------------------------------------------------------
      // FIND OUR PAYMENT
      // ------------------------------------------------------

      const paymentRef =
        db
          .collection("paymentRecords")
          .doc(
            transactionReference
          );

      const paymentSnapshot =
        await paymentRef.get();

      if (
        !paymentSnapshot.exists
      ) {

        console.warn(
          "Unknown Squad transaction:",
          transactionReference
        );

        return res.status(400).json({
          response_code: 400,
          transaction_reference:
            transactionReference,
          response_description:
            "Unknown transaction reference"
        });
      }

      const payment =
        paymentSnapshot.data();

      // ------------------------------------------------------
      // DUPLICATE CHECK
      // ------------------------------------------------------

      if (
        payment.credited === true
      ) {

        return res.status(200).json({
          response_code: 200,
          transaction_reference:
            transactionReference,
          response_description:
            "Already processed"
        });
      }

      // ------------------------------------------------------
      // IMPORTANT:
      // DO NOT TRUST THE WEBHOOK ALONE.
      //
      // Re-query Squad.
      // ------------------------------------------------------

      const verification =
        await verifySquadTransaction(
          transactionReference
        );

      const verified =
        verification?.data ||
        verification;

      const verifiedAmount =
        Number(
          verified?.transaction_amount ??
          verified?.amount
        );

      const verifiedStatus =
        verified?.transaction_status ||
        verified?.status ||
        "";

      const verifiedCurrency =
        String(
          verified?.transaction_currency_id ??
          verified?.currency ??
          "NGN"
        ).toUpperCase();

      // ------------------------------------------------------
      // SUCCESS
      // ------------------------------------------------------

      if (
        isSuccessfulPayment(
          verifiedStatus
        )
      ) {

        await settleWalletPayment({
          transactionReference,

          squadTransaction: {
            amountKobo:
              verifiedAmount,

            currency:
              verifiedCurrency
          }
        });

        return res.status(200).json({
          response_code: 200,
          transaction_reference:
            transactionReference,
          response_description:
            "Success"
        });
      }

      // ------------------------------------------------------
      // FAILURE
      // ------------------------------------------------------

      if (
        isFailedPayment(
          verifiedStatus
        )
      ) {

        await paymentRef.update({
          status:
            normalizeStatus(
              verifiedStatus
            ),

          credited:
            false,

          squadStatus:
            verifiedStatus,

          updatedAt:
            FieldValue.serverTimestamp()
        });

        return res.status(200).json({
          response_code: 200,
          transaction_reference:
            transactionReference,
          response_description:
            "Payment recorded as unsuccessful"
        });
      }

      // ------------------------------------------------------
      // PENDING
      // ------------------------------------------------------

      await paymentRef.update({
        status:
          "pending",

        squadStatus:
          verifiedStatus ||
          "Pending",

        updatedAt:
          FieldValue.serverTimestamp()
      });

      return res.status(200).json({
        response_code: 200,
        transaction_reference:
          transactionReference,
        response_description:
          "Payment pending"
      });

    } catch (error) {

      console.error(
        "Squad webhook processing error:",
        error
      );

      return res.status(500).json({
        response_code: 500,
        transaction_reference:
          transactionReference,
        response_description:
          "System malfunction"
      });
    }
  }
);

// ------------------------------------------------------------
// NOW ENABLE NORMAL JSON REQUESTS
// ------------------------------------------------------------

app.use(
  express.json({
    limit: "1mb"
  })
);

// ------------------------------------------------------------
// HEALTH CHECK
// ------------------------------------------------------------

app.get(
  "/health",
  async (req, res) => {

    return res.json({

      success:
        true,

      service:
        "Naira Master HGT Backend",

      environment:
        NODE_ENV,

      firebase:
        admin.apps.length > 0,

      squad:
        SQUAD_BASE_URL
    });
  }
);

// ------------------------------------------------------------
// INITIALIZE PAYMENT
// ------------------------------------------------------------

app.post(
  "/api/payments/initiate",

  authenticateFirebase,

  async (req, res) => {

    try {

      const uid =
        req.user.uid;

      const email =
        req.user.email ||
        req.body.email ||
        null;

      const customerName =
        req.body.customerName ||
        req.user.name ||
        "";

      const purpose =
        String(
          req.body.purpose ||
          "wallet_funding"
        );

      const amountNaira =
        Number(
          req.body.amount
        );

      // ------------------------------------------------------
      // EMAIL
      // ------------------------------------------------------

      if (!email) {

        return res.status(400).json({
          success: false,
          message:
            "Customer email is required"
        });
      }

      // ------------------------------------------------------
      // AMOUNT
      // ------------------------------------------------------

      if (
        !Number.isFinite(
          amountNaira
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Invalid payment amount"
        });
      }

      // ------------------------------------------------------
      // WALLET FUNDING
      // ------------------------------------------------------

      if (
        purpose ===
        "wallet_funding"
      ) {

        if (
          amountNaira <
          MIN_WALLET_FUNDING_NAIRA
        ) {

          return res.status(400).json({
            success: false,

            message:
              `Minimum payment amount is ₦${MIN_WALLET_FUNDING_NAIRA.toLocaleString(
                "en-NG"
              )}`
          });
        }
      }

      // ------------------------------------------------------
      // TASK CREATION
      // ------------------------------------------------------

      if (
        purpose ===
        "task_creation"
      ) {

        if (
          amountNaira !==
          TASK_CREATION_FEE_NAIRA
        ) {

          return res.status(400).json({
            success: false,

            message:
              `Task creation payment must be exactly ₦${TASK_CREATION_FEE_NAIRA.toLocaleString(
                "en-NG"
              )}`
          });
        }
      }

      // ------------------------------------------------------
      // PURPOSE WHITELIST
      // ------------------------------------------------------

      if (
        ![
          "wallet_funding",
          "task_creation"
        ].includes(purpose)
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Unsupported payment purpose"
        });
      }

      // ------------------------------------------------------
      // OUR UNIQUE REFERENCE
      // ------------------------------------------------------

      const transactionReference =
        createReference(
          purpose ===
            "task_creation"
            ? "NM-TASK"
            : "NM-WALLET"
        );

      // ------------------------------------------------------
      // CREATE LOCAL PENDING PAYMENT
      // ------------------------------------------------------

      await createPaymentRecord({

        uid,

        email,

        customerName,

        purpose,

        amountNaira,

        transactionReference
      });

      // ------------------------------------------------------
      // SQUAD METADATA
      // ------------------------------------------------------

      const metadata = {

        uid,

        purpose,

        app:
          "Naira Master",

        platform:
          "Henry Global Tech"
      };

      // ------------------------------------------------------
      // SQUAD REQUEST
      // ------------------------------------------------------

      const squadResponse =
        await squadRequest(
          "/transaction/initiate",
          {

            method:
              "POST",

            body:
              JSON.stringify({

                amount:
                  nairaToKobo(
                    amountNaira
                  ),

                email,

                currency:
                  "NGN",

                initiate_type:
                  "inline",

                transaction_ref:
                  transactionReference,

                customer_name:
                  customerName,

                callback_url:
                  SQUAD_CALLBACK_URL,

                payment_channels:
                  [
                    "card",
                    "bank",
                    "ussd",
                    "transfer"
                  ],

                metadata
              })
          }
        );

      // ------------------------------------------------------
      // CHECKOUT URL
      // ------------------------------------------------------

      const checkoutUrl =
        squadResponse?.data?.checkout_url ||
        squadResponse?.checkout_url ||
        null;

      if (!checkoutUrl) {

        await db
          .collection(
            "paymentRecords"
          )
          .doc(transactionReference)
          .update({

            status:
              "initialization_failed",

            squadResponse,

            updatedAt:
              FieldValue.serverTimestamp()
          });

        return res.status(502).json({
          success: false,
          message:
            "Squad did not return a checkout URL"
        });
      }

      // ------------------------------------------------------
      // SAVE SQUAD RESPONSE
      // ------------------------------------------------------

      await db
        .collection(
          "paymentRecords"
        )
        .doc(transactionReference)
        .update({

          checkoutUrl,

          squadResponse,

          updatedAt:
            FieldValue.serverTimestamp()
        });

      // ------------------------------------------------------
      // RETURN TO FRONTEND
      // ------------------------------------------------------

      return res.status(200).json({

        success:
          true,

        message:
          "Payment initialized",

        data: {

          transactionReference,

          checkoutUrl,

          amount:
            amountNaira,

          amountKobo:
            nairaToKobo(
              amountNaira
            ),

          purpose,

          status:
            "pending"
        }
      });

    } catch (error) {

      console.error(
        "Payment initialization error:",
        error
      );

      return res.status(
        error.status || 500
      ).json({

        success:
          false,

        message:
          error.message ||
          "Unable to initialize payment",

        squad:
          NODE_ENV ===
          "production"
            ? undefined
            : error.squad
      });
    }
  }
);

// ------------------------------------------------------------
// PAYMENT STATUS
// ------------------------------------------------------------

app.get(
  "/api/payments/:transactionReference",

  authenticateFirebase,

  async (req, res) => {

    try {

      const transactionReference =
        req.params
          .transactionReference;

      const paymentSnapshot =
        await db
          .collection(
            "paymentRecords"
          )
          .doc(
            transactionReference
          )
          .get();

      if (
        !paymentSnapshot.exists
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Payment not found"
        });
      }

      const payment =
        paymentSnapshot.data();

      if (
        payment.uid !==
        req.user.uid
      ) {

        return res.status(403).json({
          success: false,
          message:
            "You do not own this payment"
        });
      }

      return res.json({

        success:
          true,

        data: {

          transactionReference,

          amount:
            payment.amountNaira,

          purpose:
            payment.purpose,

          status:
            payment.status,

          credited:
            payment.credited ===
            true
        }
      });

    } catch (error) {

      console.error(
        "Payment status error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to read payment status"
      });
    }
  }
);

// ------------------------------------------------------------
// MANUAL SERVER-SIDE VERIFICATION
// ------------------------------------------------------------

app.post(
  "/api/payments/:transactionReference/verify",

  authenticateFirebase,

  async (req, res) => {

    try {

      const transactionReference =
        req.params
          .transactionReference;

      const paymentRef =
        db
          .collection(
            "paymentRecords"
          )
          .doc(
            transactionReference
          );

      const paymentSnapshot =
        await paymentRef.get();

      if (
        !paymentSnapshot.exists
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Payment not found"
        });
      }

      const payment =
        paymentSnapshot.data();

      if (
        payment.uid !==
        req.user.uid
      ) {

        return res.status(403).json({
          success: false,
          message:
            "You do not own this payment"
        });
      }

      // Already settled.
      if (
        payment.credited === true
      ) {

        return res.json({

          success:
            true,

          data: {

            transactionReference,

            status:
              "Successful",

            credited:
              true
          }
        });
      }

      // ------------------------------------------------------
      // VERIFY WITH SQUAD
      // ------------------------------------------------------

      const squadResponse =
        await verifySquadTransaction(
          transactionReference
        );

      const verified =
        squadResponse?.data ||
        squadResponse;

      const status =
        verified?.transaction_status ||
        verified?.status ||
        "";

      const amountKobo =
        Number(
          verified?.transaction_amount ??
          verified?.amount
        );

      const currency =
        String(
          verified?.transaction_currency_id ??
          verified?.currency ??
          "NGN"
        ).toUpperCase();

      // ------------------------------------------------------
      // SUCCESS
      // ------------------------------------------------------

      if (
        isSuccessfulPayment(
          status
        )
      ) {

        const result =
          await settleWalletPayment({

            transactionReference,

            squadTransaction: {

              amountKobo,

              currency
            }
          });

        return res.json({

          success:
            true,

          data: {

            transactionReference,

            status:
              "Successful",

            credited:
              true,

            alreadyCredited:
              result.alreadyCredited
          }
        });
      }

      // ------------------------------------------------------
      // FAILED
      // ------------------------------------------------------

      if (
        isFailedPayment(
          status
        )
      ) {

        await paymentRef.update({

          status:
            normalizeStatus(
              status
            ),

          squadStatus:
            status,

          credited:
            false,

          updatedAt:
            FieldValue.serverTimestamp()
        });

        return res.json({

          success:
            true,

          data: {

            transactionReference,

            status:
              "Failed",

            credited:
              false
          }
        });
      }

      // ------------------------------------------------------
      // PENDING
      // ------------------------------------------------------

      return res.json({

        success:
          true,

        data: {

          transactionReference,

          status:
            "Pending",

          squadStatus:
            status ||
            "Pending",

          credited:
            false
        }
      });

    } catch (error) {

      console.error(
        "Payment verification error:",
        error
      );

      return res.status(
        error.status || 500
      ).json({

        success:
          false,

        message:
          error.message ||
          "Unable to verify payment"
      });
    }
  }
);

// ------------------------------------------------------------
// BROWSER PAYMENT CALLBACK
//
// NEVER credits Firebase.
// It only sends the user back to Naira Master.
// ------------------------------------------------------------

app.get(
  "/api/payment-callback",

  async (req, res) => {

    const reference =
      req.query.reference ||
      req.query.transaction_ref ||
      req.query.transaction_reference ||
      "";

    if (FRONTEND_URL) {

      const destination =
        `${FRONTEND_URL}/payment-callback` +
        `?reference=${encodeURIComponent(
          reference
        )}`;

      return res.redirect(
        destination
      );
    }

    return res.json({

      success:
        true,

      message:
        "Payment callback received",

      reference
    });
  }
);

// ------------------------------------------------------------
// CREATE TASK AFTER SQUAD PAYMENT
//
// The task is only created after the payment record
// has already been settled successfully.
// ------------------------------------------------------------

app.post(
  "/api/tasks/create",

  authenticateFirebase,

  async (req, res) => {

    try {

      const uid =
        req.user.uid;

      const {
        paymentReference,
        task
      } = req.body;

      if (
        !paymentReference
      ) {

        return res.status(400).json({
          success: false,
          message:
            "paymentReference is required"
        });
      }

      if (
        !task ||
        typeof task !== "object"
      ) {

        return res.status(400).json({
          success: false,
          message:
            "task data is required"
        });
      }

      const paymentRef =
        db
          .collection(
            "paymentRecords"
          )
          .doc(
            String(
              paymentReference
            )
          );

      const taskRef =
        db
          .collection(
            "tasks"
          )
          .doc();

      await db.runTransaction(
        async transaction => {

          const paymentSnapshot =
            await transaction.get(
              paymentRef
            );

          if (
            !paymentSnapshot.exists
          ) {
            throw new Error(
              "Payment does not exist"
            );
          }

          const payment =
            paymentSnapshot.data();

          if (
            payment.uid !==
            uid
          ) {
            throw new Error(
              "Payment does not belong to this user"
            );
          }

          if (
            payment.purpose !==
            "task_creation"
          ) {
            throw new Error(
              "Payment is not a task creation payment"
            );
          }

          if (
            payment.status !==
              "credited" ||
            payment.credited !==
              true
          ) {
            throw new Error(
              "Task creation payment has not been confirmed"
            );
          }

          // --------------------------------------------------
          // CREATE TASK
          // --------------------------------------------------

          transaction.set(
            taskRef,
            {

              ...task,

              uid,

              creatorUid:
                uid,

              paymentReference:
                String(
                  paymentReference
                ),

              creationFee:
                TASK_CREATION_FEE_NAIRA,

              paymentStatus:
                "Paid",

              createdAt:
                FieldValue.serverTimestamp(),

              updatedAt:
                FieldValue.serverTimestamp()
            }
          );

          // --------------------------------------------------
          // TASK PAYMENT RECORD
          // --------------------------------------------------

          const historyRef =
            db
              .collection(
                "transactions"
              )
              .doc();

          transaction.set(
            historyRef,
            {

              uid,

              type:
                "payment",

              category:
                "task_creation",

              purpose:
                "task_creation",

              amount:
                TASK_CREATION_FEE_NAIRA,

              amountKobo:
                nairaToKobo(
                  TASK_CREATION_FEE_NAIRA
                ),

              currency:
                "NGN",

              reference:
                String(
                  paymentReference
                ),

              status:
                "Successful",

              source:
                "Squad",

              createdAt:
                FieldValue.serverTimestamp()
            }
          );
        }
      );

      return res.status(201).json({

        success:
          true,

        message:
          "Task created successfully",

        data: {

          taskId:
            taskRef.id,

          paymentReference:
            String(
              paymentReference
            )
        }
      });

    } catch (error) {

      console.error(
        "Task creation error:",
        error
      );

      return res.status(400).json({

        success:
          false,

        message:
          error.message ||
          "Unable to create task"
      });
    }
  }
);

// ------------------------------------------------------------
// 404
// ------------------------------------------------------------

app.use(
  (req, res) => {

    return res.status(404).json({

      success:
        false,

      message:
        "Endpoint not found",

      path:
        req.originalUrl
    });
  }
);

// ------------------------------------------------------------
// ERROR HANDLER
// ------------------------------------------------------------

app.use(
  (
    error,
    req,
    res,
    next
  ) => {

    console.error(
      "Unhandled server error:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    return res.status(500).json({

      success:
        false,

      message:
        "Internal server error"
    });
  }
);

// ------------------------------------------------------------
// START
// ------------------------------------------------------------

app.listen(
  PORT,
  () => {

    console.log(
      "================================================"
    );

    console.log(
      "NAIRA MASTER — HGT BACKEND"
    );

    console.log(
      "================================================"
    );

    console.log(
      `Environment: ${NODE_ENV}`
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      `Squad: ${SQUAD_BASE_URL}`
    );

    console.log(
      "Firebase Admin: initialized"
    );

    console.log(
      "================================================"
    );
  }
);

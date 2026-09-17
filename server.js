/**
 * ============================================================
 * NAIRA MASTER — HGT SQUAD PAYMENT BACKEND
 * ============================================================
 *
 * SINGLE-FILE SERVER
 *
 * Stack:
 *   Node.js
 *   Express
 *   Firebase Admin
 *   Squad API
 *
 * Designed for:
 *   Naira Master PWA
 *   Henry Global Tech
 *   Render
 *
 * IMPORTANT:
 *   NEVER put SQUAD_SECRET_KEY or FIREBASE_PRIVATE_KEY
 *   in frontend code.
 *
 *   Put all secrets in Render Environment Variables.
 *
 * ============================================================
 */

import "dotenv/config";

import express from "express";
import cors from "cors";
import crypto from "crypto";
import admin from "firebase-admin";


/* ============================================================
   BASIC CONFIGURATION
   ============================================================ */

const app = express();

const PORT = Number(process.env.PORT || 10000);

const NODE_ENV =
  process.env.NODE_ENV || "development";

const SQUAD_ENV =
  String(process.env.SQUAD_ENV || "sandbox").toLowerCase();

const FRONTEND_URL =
  process.env.FRONTEND_URL || "*";

const WEBHOOK_VERSION =
  String(process.env.SQUAD_WEBHOOK_VERSION || "auto").toLowerCase();


/* ============================================================
   SQUAD BASE URL
   ============================================================ */

const SQUAD_BASE_URL =
  SQUAD_ENV === "production"
    ? "https://api-d.squadco.com"
    : "https://sandbox-api-d.squadco.com";


/* ============================================================
   REQUIRED ENVIRONMENT VARIABLES
   ============================================================ */

if (!process.env.SQUAD_SECRET_KEY) {
  throw new Error(
    "Missing SQUAD_SECRET_KEY environment variable."
  );
}

if (!process.env.FIREBASE_PROJECT_ID) {
  throw new Error(
    "Missing FIREBASE_PROJECT_ID environment variable."
  );
}

if (!process.env.FIREBASE_CLIENT_EMAIL) {
  throw new Error(
    "Missing FIREBASE_CLIENT_EMAIL environment variable."
  );
}

if (!process.env.FIREBASE_PRIVATE_KEY) {
  throw new Error(
    "Missing FIREBASE_PRIVATE_KEY environment variable."
  );
}


/* ============================================================
   FIREBASE ADMIN
   ============================================================ */

admin.initializeApp({
  credential: admin.credential.cert({
    projectId:
      process.env.FIREBASE_PROJECT_ID,

    clientEmail:
      process.env.FIREBASE_CLIENT_EMAIL,

    privateKey:
      process.env.FIREBASE_PRIVATE_KEY
        .replace(/\\n/g, "\n")
  })
});

const db = admin.firestore();

const FieldValue =
  admin.firestore.FieldValue;


/* ============================================================
   EXPRESS SECURITY
   ============================================================ */

app.disable("x-powered-by");


/* ============================================================
   CORS
   ============================================================ */

app.use(
  cors({
    origin:
      FRONTEND_URL === "*"
        ? true
        : FRONTEND_URL,

    methods: [
      "GET",
      "POST",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);


/* ============================================================
   IMPORTANT WEBHOOK RAW-BODY HANDLING
   ============================================================ */

/*
 * Squad webhook signatures are generated from webhook data.
 *
 * Therefore the webhook route MUST receive the raw body
 * before express.json() modifies it.
 */

app.post(
  "/api/squad/webhook",
  express.raw({
    type: "application/json",
    limit: "2mb"
  }),
  squadWebhook
);


/* ============================================================
   NORMAL JSON BODY
   ============================================================ */

app.use(
  express.json({
    limit: "200kb"
  })
);


/* ============================================================
   HEALTH CHECK
   ============================================================ */

app.get(
  "/health",
  (_req, res) => {

    res.json({
      success: true,

      service:
        "Naira Master HGT Squad Backend",

      environment:
        SQUAD_ENV,

      status:
        "online",

      timestamp:
        new Date().toISOString()
    });

  }
);


/* ============================================================
   UTILITY FUNCTIONS
   ============================================================ */


/**
 * Generate unique merchant reference.
 */
function generateReference(prefix) {

  return (
    prefix +
    "_" +
    Date.now() +
    "_" +
    crypto
      .randomBytes(6)
      .toString("hex")
      .toUpperCase()
  );

}


/**
 * Convert Naira to kobo.
 *
 * ₦100 = 10000 kobo
 */
function nairaToKobo(amount) {

  const value =
    Number(amount);

  if (
    !Number.isFinite(value)
  ) {
    throw new Error(
      "Invalid amount."
    );
  }

  if (
    value < 100
  ) {
    throw new Error(
      "Minimum payment amount is ₦100."
    );
  }

  if (
    Math.round(value * 100) !==
    value * 100
  ) {
    throw new Error(
      "Amount can contain a maximum of two decimal places."
    );
  }

  return Math.round(
    value * 100
  );

}


/**
 * Compare strings safely.
 */
function safeEqual(a, b) {

  try {

    const aa =
      Buffer.from(
        String(a),
        "utf8"
      );

    const bb =
      Buffer.from(
        String(b),
        "utf8"
      );

    if (
      aa.length !==
      bb.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      aa,
      bb
    );

  } catch {

    return false;

  }

}


/**
 * Normalize Firebase private key.
 */
function normalizePrivateKey(key) {

  return String(key)
    .replace(/\\n/g, "\n");

}


/* ============================================================
   FIREBASE AUTHENTICATION
   ============================================================ */

async function authenticateFirebaseUser(
  req,
  res,
  next
) {

  try {

    const authorization =
      req.headers.authorization || "";

    if (
      !authorization.startsWith(
        "Bearer "
      )
    ) {

      return res.status(401).json({

        success: false,

        message:
          "Firebase authentication token is required."

      });

    }

    const token =
      authorization
        .substring(7)
        .trim();

    const decoded =
      await admin
        .auth()
        .verifyIdToken(token);

    req.user =
      decoded;

    next();

  } catch (error) {

    console.error(
      "Firebase authentication error:",
      error
    );

    return res.status(401).json({

      success: false,

      message:
        "Invalid or expired Firebase authentication token."

    });

  }

}


/* ============================================================
   SQUAD API REQUEST
   ============================================================ */

async function squadRequest(
  endpoint,
  options = {}
) {

  const response =
    await fetch(
      SQUAD_BASE_URL + endpoint,
      {

        method:
          options.method || "GET",

        headers: {

          "Authorization":
            `Bearer ${process.env.SQUAD_SECRET_KEY}`,

          "Content-Type":
            "application/json",

          ...(options.headers || {})

        },

        body:
          options.body
            ? JSON.stringify(
                options.body
              )
            : undefined

      }
    );


  const text =
    await response.text();

  let data;

  try {

    data =
      JSON.parse(text);

  } catch {

    data = {
      raw: text
    };

  }


  if (
    !response.ok
  ) {

    const error =
      new Error(
        data?.message ||
        "Squad API request failed."
      );

    error.status =
      response.status;

    error.squadResponse =
      data;

    throw error;

  }


  return data;

}


/* ============================================================
   SQUAD PAYMENT INITIALIZATION
   ============================================================ */

async function createSquadCheckout({

  amountKobo,

  email,

  customerName,

  reference,

  callbackUrl,

  metadata

}) {

  const channels =
    (
      process.env.SQUAD_PAYMENT_CHANNELS ||
      "card,bank,ussd,transfer"
    )
      .split(",")
      .map(
        x => x.trim()
      )
      .filter(Boolean);


  const payload = {

    amount:
      amountKobo,

    email:
      email,

    currency:
      "NGN",

    initiate_type:
      "inline",

    transaction_ref:
      reference,

    customer_name:
      customerName,

    callback_url:
      callbackUrl,

    payment_channels:
      channels,

    metadata:
      metadata,

    pass_charge:
      process.env.SQUAD_PASS_CHARGE === "true"

  };


  const response =
    await squadRequest(
      "/transaction/initiate",
      {

        method:
          "POST",

        body:
          payload

      }
    );


  const data =
    response?.data ||
    response;


  const checkoutUrl =
    data?.checkout_url ||
    data?.checkoutUrl;


  if (!checkoutUrl) {

    throw new Error(
      "Squad did not return checkout_url."
    );

  }


  return {

    checkoutUrl,

    transactionRef:
      data?.transaction_ref ||
      reference,

    response

  };

}


/* ============================================================
   ADD MONEY
   ============================================================ */

/*
 * POST
 *
 * /api/payments/add-money
 *
 * Body:
 *
 * {
 *   "amount": 5000
 * }
 */

app.post(
  "/api/payments/add-money",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const uid =
        req.user.uid;

      const email =
        req.user.email ||
        req.body.email;

      const customerName =
        req.body.customerName ||
        req.user.name ||
        "Naira Master User";


      if (!email) {

        return res.status(400).json({

          success: false,

          message:
            "Customer email is required."

        });

      }


      const amountNaira =
        Number(
          req.body.amount
        );


      const amountKobo =
        nairaToKobo(
          amountNaira
        );


      const reference =
        generateReference(
          "NM_WALLET"
        );


      const paymentRef =
        db
          .collection(
            "squadPayments"
          )
          .doc(reference);


      await paymentRef.create({

        reference,

        uid,

        email,

        customerName,

        amountNaira,

        amountKobo,

        currency:
          "NGN",

        purpose:
          "wallet_funding",

        status:
          "pending",

        credited:
          false,

        createdAt:
          FieldValue.serverTimestamp(),

        updatedAt:
          FieldValue.serverTimestamp()

      });


      const callbackUrl =
        process.env.FRONTEND_URL
          ? (
              process.env.FRONTEND_URL
                .replace(/\/$/, "") +
              "/?payment=squad-complete"
            )
          : undefined;


      const checkout =
        await createSquadCheckout({

          amountKobo,

          email,

          customerName,

          reference,

          callbackUrl,

          metadata: {

            uid,

            purpose:
              "wallet_funding",

            naira_master_reference:
              reference

          }

        });


      await paymentRef.update({

        checkoutUrl:
          checkout.checkoutUrl,

        squadReference:
          checkout.transactionRef,

        squadInitializeResponse:
          checkout.response,

        updatedAt:
          FieldValue.serverTimestamp()

      });


      return res.json({

        success: true,

        reference,

        checkoutUrl:
          checkout.checkoutUrl,

        amount:
          amountNaira,

        currency:
          "NGN"

      });

    } catch (error) {

      console.error(
        "ADD MONEY ERROR:",
        error
      );


      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to initialize Add Money payment."

      });

    }

  }
);


/* ============================================================
   PAYMENT STATUS
   ============================================================ */

app.get(
  "/api/payments/status/:reference",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const reference =
        String(
          req.params.reference
        );


      const snapshot =
        await db
          .collection(
            "squadPayments"
          )
          .doc(reference)
          .get();


      if (
        !snapshot.exists
      ) {

        return res.status(404).json({

          success: false,

          message:
            "Payment not found."

        });

      }


      const payment =
        snapshot.data();


      if (
        payment.uid !==
        req.user.uid
      ) {

        return res.status(403).json({

          success: false,

          message:
            "You are not authorized to view this payment."

        });

      }


      return res.json({

        success: true,

        payment: {

          reference,

          amount:
            payment.amountNaira,

          currency:
            payment.currency,

          purpose:
            payment.purpose,

          status:
            payment.status,

          credited:
            Boolean(
              payment.credited
            ),

          gatewayRef:
            payment.gatewayRef ||
            null,

          createdAt:
            payment.createdAt ||
            null,

          completedAt:
            payment.completedAt ||
            null

        }

      });

    } catch (error) {

      console.error(
        "STATUS ERROR:",
        error
      );


      res.status(500).json({

        success: false,

        message:
          "Unable to retrieve payment status."

      });

    }

  }
);


/* ============================================================
   SQUAD WEBHOOK SIGNATURE
   ============================================================ */

/*
 * Squad documents:
 *
 * V1:
 *   HMAC of entire webhook body.
 *
 * V2/V3:
 *   HMAC of:
 *
 * transaction_reference
 * virtual_account_number
 * currency
 * principal_amount
 * settled_amount
 * customer_identifier
 *
 * separated with |.
 */

function verifySquadWebhookSignature(
  rawBody,
  payload,
  signature
) {

  if (
    !signature
  ) {

    return false;

  }


  const body =
    payload?.Body ||
    payload?.body ||
    payload?.data ||
    payload;


  const transactionReference =
    payload?.transaction_reference ||
    body?.transaction_reference ||
    payload?.TransactionRef ||
    body?.transaction_ref;


  const virtualAccountNumber =
    payload?.virtual_account_number ||
    body?.virtual_account_number;


  const currency =
    payload?.currency ||
    body?.currency;


  const principalAmount =
    payload?.principal_amount ||
    body?.principal_amount;


  const settledAmount =
    payload?.settled_amount ||
    body?.settled_amount;


  const customerIdentifier =
    payload?.customer_identifier ||
    body?.customer_identifier;


  const sixFieldsAvailable =
    transactionReference !== undefined &&
    virtualAccountNumber !== undefined &&
    currency !== undefined &&
    principalAmount !== undefined &&
    settledAmount !== undefined &&
    customerIdentifier !== undefined;


  /*
   * Explicit V2/V3 mode.
   */

  if (
    WEBHOOK_VERSION === "v2" ||
    WEBHOOK_VERSION === "v3"
  ) {

    if (
      !sixFieldsAvailable
    ) {

      return false;

    }


    const signingString =

      `${transactionReference}|` +
      `${virtualAccountNumber}|` +
      `${currency}|` +
      `${principalAmount}|` +
      `${settledAmount}|` +
      `${customerIdentifier}`;


    const expected =
      crypto
        .createHmac(
          "sha512",
          process.env.SQUAD_SECRET_KEY
        )
        .update(
          signingString,
          "utf8"
        )
        .digest(
          "hex"
        );


    if (
      safeEqual(
        expected,
        signature
      )
    ) {

      return true;

    }


    /*
     * Some Squad implementations/docs
     * use SHA256 examples.
     *
     * Try it as compatibility fallback.
     */

    const expectedSha256 =
      crypto
        .createHmac(
          "sha256",
          process.env.SQUAD_SECRET_KEY
        )
        .update(
          signingString,
          "utf8"
        )
        .digest(
          "hex"
        );


    return safeEqual(
      expectedSha256,
      signature
    );

  }


  /*
   * AUTO:
   *
   * Try six-field signature first.
   */

  if (
    sixFieldsAvailable
  ) {

    const signingString =

      `${transactionReference}|` +
      `${virtualAccountNumber}|` +
      `${currency}|` +
      `${principalAmount}|` +
      `${settledAmount}|` +
      `${customerIdentifier}`;


    const sha512 =
      crypto
        .createHmac(
          "sha512",
          process.env.SQUAD_SECRET_KEY
        )
        .update(
          signingString
        )
        .digest(
          "hex"
        );


    if (
      safeEqual(
        sha512,
        signature
      )
    ) {

      return true;

    }


    const sha256 =
      crypto
        .createHmac(
          "sha256",
          process.env.SQUAD_SECRET_KEY
        )
        .update(
          signingString
        )
        .digest(
          "hex"
        );


    if (
      safeEqual(
        sha256,
        signature
      )
    ) {

      return true;

    }

  }


  /*
   * V1 fallback:
   *
   * Entire raw webhook body.
   */

  const bodyHash =
    crypto
      .createHmac(
        "sha512",
        process.env.SQUAD_SECRET_KEY
      )
      .update(
        rawBody
      )
      .digest(
        "hex"
      );


  if (
    safeEqual(
      bodyHash,
      signature
    )
  ) {

    return true;

  }


  const bodyHashSha256 =
    crypto
      .createHmac(
        "sha256",
        process.env.SQUAD_SECRET_KEY
      )
      .update(
        rawBody
      )
      .digest(
        "hex"
      );


  return safeEqual(
    bodyHashSha256,
    signature
  );

}


/* ============================================================
   EXTRACT NORMAL CHECKOUT WEBHOOK
   ============================================================ */

function extractCheckoutWebhook(
  payload
) {

  const body =
    payload?.Body ||
    payload?.body ||
    payload?.data ||
    payload;


  return {

    event:
      payload?.Event ||
      payload?.event ||
      null,

    reference:
      body?.transaction_ref ||
      payload?.TransactionRef ||
      payload?.transaction_reference ||
      null,

    status:
      body?.transaction_status ||
      body?.status ||
      payload?.transaction_status ||
      payload?.status ||
      null,

    amountKobo:
      Number(
        body?.amount ||
        body?.principal_amount ||
        0
      ),

    currency:
      body?.currency ||
      payload?.currency ||
      "NGN",

    gatewayRef:
      body?.gateway_ref ||
      body?.gateway_transaction_ref ||
      null,

    metadata:
      body?.meta ||
      body?.metadata ||
      payload?.meta ||
      payload?.metadata ||
      {}

  };

}


/* ============================================================
   CREDIT WALLET
   ============================================================ */

async function creditWalletFromPayment(
  paymentReference,
  webhook
) {

  const paymentDoc =
    db
      .collection(
        "squadPayments"
      )
      .doc(
        paymentReference
      );


  return db.runTransaction(
    async transaction => {

      const paymentSnapshot =
        await transaction.get(
          paymentDoc
        );


      if (
        !paymentSnapshot.exists
      ) {

        return {

          found:
            false,

          alreadyProcessed:
            false

        };

      }


      const payment =
        paymentSnapshot.data();


      /*
       * DUPLICATE PROTECTION
       */

      if (
        payment.credited === true ||
        payment.status ===
          "successful"
      ) {

        return {

          found:
            true,

          alreadyProcessed:
            true,

          uid:
            payment.uid,

          amount:
            payment.amountNaira

        };

      }


      /*
       * STATUS CHECK
       */

      const status =
        String(
          webhook.status ||
          webhook.event ||
          ""
        ).toLowerCase();


      const successful =

        status ===
          "success" ||

        status ===
          "successful" ||

        status ===
          "charge_successful";


      if (
        !successful
      ) {

        transaction.update(
          paymentDoc,
          {

            status:
              "failed",

            squadStatus:
              webhook.status ||
              null,

            updatedAt:
              FieldValue.serverTimestamp()

          }
        );


        return {

          found:
            true,

          alreadyProcessed:
            false,

          successful:
            false,

          uid:
            payment.uid,

          amount:
            payment.amountNaira

        };

      }


      /*
       * CURRENCY CHECK
       */

      if (
        String(
          webhook.currency
        ).toUpperCase() !==
        "NGN"
      ) {

        throw new Error(
          "Payment currency is not NGN."
        );

      }


      /*
       * AMOUNT CHECK
       */

      if (
        Number(
          webhook.amountKobo
        ) !==
        Number(
          payment.amountKobo
        )
      ) {

        throw new Error(

          "Payment amount mismatch."

        );

      }


      const userDoc =
        db
          .collection(
            "users"
          )
          .doc(
            payment.uid
          );


      const userSnapshot =
        await transaction.get(
          userDoc
        );


      if (
        !userSnapshot.exists
      ) {

        throw new Error(
          "Naira Master user does not exist."
        );

      }


      const user =
        userSnapshot.data() ||
        {};


      const oldBalance =
        Number(
          user.balance || 0
        );


      const creditAmount =
        Number(
          payment.amountNaira
        );


      const newBalance =
        oldBalance +
        creditAmount;


      /*
       * WALLET UPDATE
       */

      transaction.update(
        userDoc,
        {

          balance:
            newBalance,

          updatedAt:
            FieldValue.serverTimestamp()

        }
      );


      /*
       * TRANSACTION RECORD
       */

      const transactionDoc =
        db
          .collection(
            "transactions"
          )
          .doc(
            paymentReference
          );


      transaction.set(
        transactionDoc,
        {

          uid:
            payment.uid,

          type:
            "credit",

          category:
            "wallet_funding",

          purpose:
            "Add Money",

          amount:
            creditAmount,

          currency:
            "NGN",

          status:
            "Successful",

          reference:
            paymentReference,

          gatewayRef:
            webhook.gatewayRef ||
            null,

          previousBalance:
            oldBalance,

          newBalance:
            newBalance,

          source:
            "Squad",

          createdAt:
            FieldValue.serverTimestamp()

        }
      );


      /*
       * PAYMENT RECORD
       */

      transaction.update(
        paymentDoc,
        {

          status:
            "successful",

          credited:
            true,

          gatewayRef:
            webhook.gatewayRef ||
            null,

          completedAt:
            FieldValue.serverTimestamp(),

          updatedAt:
            FieldValue.serverTimestamp()

        }
      );


      return {

        found:
          true,

        alreadyProcessed:
          false,

        successful:
          true,

        uid:
          payment.uid,

        amount:
          creditAmount,

        newBalance

      };

    }
  );

}


/* ============================================================
   SQUAD WEBHOOK
   ============================================================ */

async function squadWebhook(
  req,
  res
) {

  const rawBody =
    Buffer.isBuffer(req.body)
      ? req.body
      : Buffer.from(
          req.body || ""
        );


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

      response_code:
        400,

      response_description:
        "Invalid JSON"

    });

  }


  const signatureHeader =
    req.headers[
      "x-squad-signature"
    ];


  const signature =
    Array.isArray(
      signatureHeader
    )
      ? signatureHeader[0]
      : signatureHeader;


  const valid =
    verifySquadWebhookSignature(
      rawBody,
      payload,
      signature
    );


  if (
    !valid
  ) {

    console.warn(
      "Rejected Squad webhook: invalid signature."
    );


    return res.status(401).json({

      response_code:
        400,

      response_description:
        "Invalid webhook signature"

    });

  }


  try {

    const webhook =
      extractCheckoutWebhook(
        payload
      );


    if (
      !webhook.reference
    ) {

      return res.status(400).json({

        response_code:
          400,

        response_description:
          "Transaction reference missing"

      });

    }


    const result =
      await creditWalletFromPayment(
        webhook.reference,
        webhook
      );


    /*
     * Squad expects a successful acknowledgement.
     */

    return res.status(200).json({

      response_code:
        200,

      transaction_reference:
        webhook.reference,

      response_description:
        result.alreadyProcessed
          ? "Already processed"
          : "Success"

    });

  } catch (error) {

    console.error(
      "SQUAD WEBHOOK ERROR:",
      error
    );


    return res.status(500).json({

      response_code:
        500,

      response_description:
        "System malfunction"

    });

  }

}


/* ============================================================
   CREATE TASK PAYMENT
   ============================================================ */

/*
 * Existing Naira Master source uses:
 *
 * TASK CREATION FEE = ₦1,000
 *
 * We keep this configurable through ENV.
 */

const TASK_CREATION_FEE =
  Number(
    process.env.TASK_CREATION_FEE ||
    1000
  );


app.post(
  "/api/payments/create-task",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const uid =
        req.user.uid;

      const email =
        req.user.email ||
        req.body.email;


      if (!email) {

        return res.status(400).json({

          success: false,

          message:
            "Customer email is required."

        });

      }


      const taskPayload =
        req.body.taskPayload;


      if (
        !taskPayload ||
        typeof taskPayload !==
          "object"
      ) {

        return res.status(400).json({

          success: false,

          message:
            "taskPayload is required."

        });

      }


      const amountNaira =
        TASK_CREATION_FEE;


      const amountKobo =
        nairaToKobo(
          amountNaira
        );


      const reference =
        generateReference(
          "NM_TASK"
        );


      const paymentDoc =
        db
          .collection(
            "squadPayments"
          )
          .doc(
            reference
          );


      await paymentDoc.create({

        reference,

        uid,

        email,

        amountNaira,

        amountKobo,

        currency:
          "NGN",

        purpose:
          "task_creation",

        status:
          "pending",

        credited:
          false,

        taskPayload,

        createdAt:
          FieldValue.serverTimestamp(),

        updatedAt:
          FieldValue.serverTimestamp()

      });


      const callbackUrl =
        process.env.FRONTEND_URL
          ? (
              process.env.FRONTEND_URL
                .replace(/\/$/, "") +
              "/?payment=task-complete"
            )
          : undefined;


      const checkout =
        await createSquadCheckout({

          amountKobo,

          email,

          customerName:
            req.user.name ||
            "Naira Master User",

          reference,

          callbackUrl,

          metadata: {

            uid,

            purpose:
              "task_creation",

            naira_master_reference:
              reference

          }

        });


      await paymentDoc.update({

        checkoutUrl:
          checkout.checkoutUrl,

        squadReference:
          checkout.transactionRef,

        updatedAt:
          FieldValue.serverTimestamp()

      });


      return res.json({

        success: true,

        reference,

        checkoutUrl:
          checkout.checkoutUrl,

        amount:
          amountNaira

      });

    } catch (error) {

      console.error(
        "TASK PAYMENT ERROR:",
        error
      );


      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to initialize task payment."

      });

    }

  }
);


/* ============================================================
   VIRTUAL ACCOUNT — CREATE
   ============================================================ */

/*
 * IMPORTANT:
 *
 * Squad requires certain customer information for B2C
 * virtual-account creation, including BVN and other
 * identifying information.
 *
 * The Naira Master frontend should NEVER send the
 * Squad secret key.
 *
 * This endpoint authenticates the Firebase user and
 * calls Squad server-side.
 */

app.post(
  "/api/virtual-accounts/create",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const uid =
        req.user.uid;


      const {

        firstName,

        lastName,

        middleName,

        mobileNumber,

        dob,

        bvn,

        gender,

        address,

        beneficiaryAccount

      } = req.body;


      if (
        !firstName ||
        !lastName ||
        !mobileNumber ||
        !dob ||
        !bvn ||
        !gender ||
        !address
      ) {

        return res.status(400).json({

          success: false,

          message:
            "Required virtual-account information is missing."

        });

      }


      const customerIdentifier =
        `NM_${uid}`;


      const squadResponse =
        await squadRequest(
          "/virtual-account",
          {

            method:
              "POST",

            body: {

              customer_identifier:
                customerIdentifier,

              first_name:
                firstName,

              last_name:
                lastName,

              middle_name:
                middleName,

              mobile_num:
                mobileNumber,

              email:
                req.user.email ||
                req.body.email,

              bvn,

              dob,

              gender,

              address,

              beneficiary_account:
                beneficiaryAccount ||
                process.env.SQUAD_BENEFICIARY_ACCOUNT ||
                undefined

            }

          }
        );


      const account =
        squadResponse?.data ||
        {};


      /*
       * Save virtual-account information
       * against Firebase UID.
       */

      await db
        .collection(
          "users"
        )
        .doc(uid)
        .set(

          {

            squadVirtualAccount: {

              customerIdentifier,

              accountNumber:
                account.virtual_account_number ||
                null,

              bankCode:
                account.bank_code ||
                null,

              beneficiaryAccount:
                account.beneficiary_account ||
                null,

              createdAt:
                FieldValue.serverTimestamp()

            }

          },

          {
            merge:
              true
          }

        );


      return res.json({

        success: true,

        customerIdentifier,

        virtualAccount:

          account.virtual_account_number ||
          null,

        bankCode:
          account.bank_code ||
          null,

        beneficiaryAccount:
          account.beneficiary_account ||
          null

      });

    } catch (error) {

      console.error(
        "VIRTUAL ACCOUNT CREATE ERROR:",
        error
      );


      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to create virtual account.",

        squad:
          error.squadResponse ||
          null

      });

    }

  }
);


/* ============================================================
   VIRTUAL ACCOUNT — GET BY CUSTOMER IDENTIFIER
   ============================================================ */

app.get(
  "/api/virtual-accounts/me",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const customerIdentifier =
        `NM_${req.user.uid}`;


      const response =
        await squadRequest(
          `/virtual-account/${encodeURIComponent(
            customerIdentifier
          )}`
        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Virtual account not found."

      });

    }

  }
);


/* ============================================================
   VIRTUAL ACCOUNT — GET BY ACCOUNT NUMBER
   ============================================================ */

app.get(
  "/api/virtual-accounts/account/:accountNumber",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const accountNumber =
        String(
          req.params.accountNumber
        );


      const response =
        await squadRequest(
          `/virtual-account/customer/${encodeURIComponent(
            accountNumber
          )}`
        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Virtual account not found."

      });

    }

  }
);


/* ============================================================
   VIRTUAL ACCOUNT — CUSTOMER TRANSACTIONS
   ============================================================ */

app.get(
  "/api/virtual-accounts/transactions",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const customerIdentifier =
        `NM_${req.user.uid}`;


      const response =
        await squadRequest(

          `/virtual-account/customer/transactions/${encodeURIComponent(
            customerIdentifier
          )}`

        );


      return res.json({

        success: true,

        data:
          response?.data ||
          []

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to retrieve virtual-account transactions."

      });

    }

  }
);


/* ============================================================
   MERCHANT VIRTUAL ACCOUNTS
   ============================================================ */

app.get(
  "/api/virtual-accounts/merchant/accounts",
  async (req, res) => {

    try {

      const query =
        new URLSearchParams();


      if (
        req.query.page
      ) {

        query.set(
          "page",
          req.query.page
        );

      }


      if (
        req.query.perPage
      ) {

        query.set(
          "perPage",
          req.query.perPage
        );

      }


      if (
        req.query.startDate
      ) {

        query.set(
          "startDate",
          req.query.startDate
        );

      }


      if (
        req.query.endDate
      ) {

        query.set(
          "endDate",
          req.query.endDate
        );

      }


      const response =
        await squadRequest(

          `/virtual-account/merchant/accounts?${query.toString()}`

        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to retrieve merchant virtual accounts."

      });

    }

  }
);


/* ============================================================
   MERCHANT VIRTUAL ACCOUNT TRANSACTIONS
   ============================================================ */

app.get(
  "/api/virtual-accounts/merchant/transactions",
  async (req, res) => {

    try {

      const response =
        await squadRequest(
          "/virtual-account/merchant/transactions"
        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to retrieve merchant transactions."

      });

    }

  }
);


/* ============================================================
   MERCHANT VIRTUAL ACCOUNT TRANSACTIONS — FILTERED
   ============================================================ */

app.get(
  "/api/virtual-accounts/merchant/transactions/all",
  async (req, res) => {

    try {

      const allowed = [

        "page",

        "perPage",

        "virtualAccount",

        "customerIdentifier",

        "startDate",

        "endDate",

        "transactionReference",

        "session_id",

        "dir"

      ];


      const query =
        new URLSearchParams();


      for (
        const key of allowed
      ) {

        if (
          req.query[key] !==
          undefined
        ) {

          query.set(
            key,
            req.query[key]
          );

        }

      }


      const response =
        await squadRequest(

          `/virtual-account/merchant/transactions/all?${query.toString()}`

        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to retrieve filtered merchant transactions."

      });

    }

  }
);


/* ============================================================
   VIRTUAL ACCOUNT WEBHOOK ERROR LOG
   ============================================================ */

app.get(
  "/api/virtual-accounts/webhook-logs",
  async (req, res) => {

    try {

      const query =
        new URLSearchParams();


      if (
        req.query.page
      ) {

        query.set(
          "page",
          req.query.page
        );

      }


      if (
        req.query.perPage
      ) {

        query.set(
          "perPage",
          req.query.perPage
        );

      }


      const response =
        await squadRequest(

          `/virtual-account/webhook/logs?${query.toString()}`

        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to retrieve webhook error logs."

      });

    }

  }
);


/* ============================================================
   DELETE PROCESSED WEBHOOK ERROR
   ============================================================ */

app.delete(
  "/api/virtual-accounts/webhook-logs/:transactionReference",
  async (req, res) => {

    try {

      const reference =
        encodeURIComponent(
          req.params.transactionReference
        );


      const response =
        await squadRequest(

          `/virtual-account/webhook/logs/${reference}`,

          {

            method:
              "DELETE"

          }

        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to delete webhook log."

      });

    }

  }
);


/* ============================================================
   QUERY SQUAD TRANSACTION
   ============================================================ */

/*
 * Squad's transaction API requires dates.
 *
 * This endpoint is intentionally server-side.
 */

app.get(
  "/api/squad/transactions",
  authenticateFirebaseUser,
  async (req, res) => {

    try {

      const today =
        new Date();

      const endDate =
        req.query.end_date ||
        today
          .toISOString()
          .slice(
            0,
            10
          );


      const startDate =
        req.query.start_date ||
        new Date(
          today.getTime() -
          30 *
          24 *
          60 *
          60 *
          1000
        )
          .toISOString()
          .slice(
            0,
            10
          );


      const query =
        new URLSearchParams({

          start_date:
            startDate,

          end_date:
            endDate

        });


      if (
        req.query.reference
      ) {

        query.set(
          "reference",
          req.query.reference
        );

      }


      if (
        req.query.page
      ) {

        query.set(
          "page",
          req.query.page
        );

      }


      if (
        req.query.perpage
      ) {

        query.set(
          "perpage",
          req.query.perpage
        );

      }


      const response =
        await squadRequest(

          `/transaction?${query.toString()}`

        );


      return res.json({

        success: true,

        data:
          response?.data ||
          response

      });

    } catch (error) {

      return res.status(
        error.status || 400
      ).json({

        success: false,

        message:
          error.message ||
          "Unable to query Squad transactions."

      });

    }

  }
);


/* ============================================================
   GLOBAL 404
   ============================================================ */

app.use(
  (_req, res) => {

    res.status(404).json({

      success: false,

      message:
        "Naira Master API route not found."

    });

  }
);


/* ============================================================
   GLOBAL ERROR HANDLER
   ============================================================ */

app.use(
  (error, _req, res, _next) => {

    console.error(
      "GLOBAL SERVER ERROR:",
      error
    );


    res.status(500).json({

      success: false,

      message:
        "Internal server error."

    });

  }
);


/* ============================================================
   START SERVER
   ============================================================ */

app.listen(
  PORT,
  () => {

    console.log(
      "================================================"
    );

    console.log(
      "NAIRA MASTER HGT SQUAD SERVER"
    );

    console.log(
      "================================================"
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      `Environment: ${NODE_ENV}`
    );

    console.log(
      `Squad environment: ${SQUAD_ENV}`
    );

    console.log(
      `Squad API: ${SQUAD_BASE_URL}`
    );

    console.log(
      "Server is running."
    );

    console.log(
      "================================================"
    );

  }
);

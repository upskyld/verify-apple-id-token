import { createRemoteJWKSet, jwtVerify } from "jose";
import * as jwt from "jsonwebtoken";
import { VerifyAppleIdTokenParams } from "./types";

export const APPLE_BASE_URL = "https://appleid.apple.com";
export const JWKS_APPLE_URI = "/auth/keys";

export const getApplePublicKey = async (kid: string, alg: string) => {
  const JWKS = createRemoteJWKSet(new URL(`${APPLE_BASE_URL}${JWKS_APPLE_URI}`));
  const key = await JWKS({
    alg,
    kid,
  });
  return key;
};

export const verifyToken = async (params: VerifyAppleIdTokenParams) => {
  const decoded = jwt.decode(params.idToken, { complete: true });
  const { kid, alg } = decoded.header;

  const applePublicKey = await getApplePublicKey(kid, alg);
  const { payload: jwtClaims } = await jwtVerify(params.idToken, applePublicKey);

  if (jwtClaims?.nonce !== params.nonce) {
    throw new Error(`The nonce parameter does not match this client - nonce: ${jwtClaims.nonce} | expected: ${params.nonce}`);
  }

  if (jwtClaims?.iss !== APPLE_BASE_URL) {
    throw new Error(`The iss does not match the Apple URL - iss: ${jwtClaims.iss} | expected: ${APPLE_BASE_URL}`);
  }

  const isFounded = [].concat(jwtClaims.aud).some((aud) => [].concat(params.clientId).includes(aud));

  if (isFounded) {
    ["email_verified", "is_private_email"].forEach((field) => {
      if (jwtClaims[field] !== undefined) {
        jwtClaims[field] = Boolean(jwtClaims[field]);
      }
    });

    return jwtClaims;
  }

  throw new Error(`The aud parameter does not include this client - is: ${jwtClaims.aud} | expected: ${params.clientId}`);
};

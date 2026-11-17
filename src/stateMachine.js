'use strict';

const crypto = require('node:crypto');

const STATES = Object.freeze({
  PENDING: 'pending',
  APPROVED: 'approved',
  DENIED: 'denied',
  EXPIRED: 'expired',
  CONSUMED: 'consumed',
});

class MfaPushError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'MfaPushError';
    this.code = code;
  }
}

const ERR = Object.freeze({
  CHALLENGE_EXISTS: 'ERR_CHALLENGE_EXISTS',
  CHALLENGE_NOT_FOUND: 'ERR_CHALLENGE_NOT_FOUND',
  INVALID_STATE: 'ERR_INVALID_STATE',
  EXPIRED: 'ERR_EXPIRED',
  DEVICE_MISMATCH: 'ERR_DEVICE_MISMATCH',
  ACTION_MISMATCH: 'ERR_ACTION_MISMATCH',
  NONCE_MISMATCH: 'ERR_NONCE_MISMATCH',
  NONCE_REPLAY: 'ERR_NONCE_REPLAY',
  BAD_SIGNATURE: 'ERR_BAD_SIGNATURE',
  ALREADY_CONSUMED: 'ERR_ALREADY_CONSUMED',
});

function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function approvalPayload({ challengeId, accountId, actionDigest, nonce, decision }) {
  return ['mfa-push-v1', challengeId, accountId, actionDigest, nonce, decision].join('|');
}

function signApproval(deviceKey, fields) {
  return crypto
    .createHmac('sha256', String(deviceKey))
    .update(approvalPayload(fields))
    .digest('hex');
}

class MfaPushStateMachine {
  constructor(options = {}) {
    this._now = options.now || (() => Date.now());
    this._requireSignature = options.requireSignature !== false;
    this._challenges = new Map();
    this._usedNoncesByAccount = new Map();
  }

  createChallenge({ challengeId, accountId, deviceKey, actionDigest, nonce, expiresAt }) {
    for (const [field, value] of Object.entries({ challengeId, accountId, deviceKey, actionDigest, nonce })) {
      if (typeof value !== 'string' || value.length === 0) {
        throw new MfaPushError(ERR.CHALLENGE_NOT_FOUND, `missing or invalid field: ${field}`);
      }
    }
    if (!Number.isFinite(expiresAt)) {
      throw new MfaPushError(ERR.CHALLENGE_NOT_FOUND, 'expiresAt must be a finite timestamp (ms)');
    }
    if (this._challenges.has(challengeId)) {
      throw new MfaPushError(ERR.CHALLENGE_EXISTS, `challenge already exists: ${challengeId}`);
    }
    if (this._nonceUsed(accountId, nonce)) {
      throw new MfaPushError(ERR.NONCE_REPLAY, `nonce already used for account: ${accountId}`);
    }
    const record = {
      challengeId,
      accountId,
      deviceKey,
      actionDigest,
      nonce,
      expiresAt,
      state: STATES.PENDING,
      decision: null,
    };
    this._challenges.set(challengeId, record);
    this._markNonceUsed(accountId, nonce);
    return { challengeId, state: record.state, expiresAt };
  }

  approve({ challengeId, deviceKey, actionDigest, nonce, signature }) {
    const record = this._decide(challengeId, { deviceKey, actionDigest, nonce, signature, decision: 'approve' });
    return { challengeId: record.challengeId, state: record.state };
  }

  deny({ challengeId, deviceKey, nonce, signature }) {
    const record = this._getUsable(challengeId);
    this._assertDevice(record, deviceKey);
    this._assertNonce(record, nonce);
    if (this._requireSignature) {
      this._assertSignature(record, { deviceKey, signature, decision: 'deny' });
    }
    record.state = STATES.DENIED;
    record.decision = 'deny';
    return { challengeId: record.challengeId, state: record.state };
  }

  consume({ challengeId, deviceKey, actionDigest, nonce }) {
    const record = this._get(challengeId);
    this._refreshExpiry(record);
    if (record.state === STATES.CONSUMED) {
      throw new MfaPushError(ERR.ALREADY_CONSUMED, `challenge already consumed: ${challengeId}`);
    }
    if (record.state !== STATES.APPROVED) {
      throw new MfaPushError(ERR.INVALID_STATE, `cannot consume challenge in state: ${record.state}`);
    }
    this._assertDevice(record, deviceKey);
    this._assertAction(record, actionDigest);
    this._assertNonce(record, nonce);
    record.state = STATES.CONSUMED;
    return { challengeId: record.challengeId, state: record.state };
  }

  rebindDevice({ accountId, newDeviceKey }) {
    if (typeof newDeviceKey !== 'string' || newDeviceKey.length === 0) {
      throw new MfaPushError(ERR.DEVICE_MISMATCH, 'newDeviceKey must be a non-empty string');
    }
    let invalidated = 0;
    for (const record of this._challenges.values()) {
      if (
        record.accountId === accountId &&
        (record.state === STATES.PENDING || record.state === STATES.APPROVED)
      ) {
        record.state = STATES.DENIED;
        record.decision = 'device_rebind';
        invalidated += 1;
      }
    }
    return { accountId, invalidated };
  }

  getState(challengeId) {
    const record = this._get(challengeId);
    this._refreshExpiry(record);
    return record.state;
  }

  sweep(now = this._now()) {
    let expired = 0;
    for (const record of this._challenges.values()) {
      if (record.state === STATES.PENDING && record.expiresAt <= now) {
        record.state = STATES.EXPIRED;
        expired += 1;
      }
    }
    return expired;
  }

  _decide(challengeId, { deviceKey, actionDigest, nonce, signature, decision }) {
    const record = this._getUsable(challengeId);
    this._assertDevice(record, deviceKey);
    this._assertAction(record, actionDigest);
    this._assertNonce(record, nonce);
    if (this._requireSignature) {
      this._assertSignature(record, { deviceKey, actionDigest, nonce, signature, decision });
    }
    record.state = STATES.APPROVED;
    record.decision = 'approve';
    return record;
  }

  _get(challengeId) {
    const record = this._challenges.get(challengeId);
    if (!record) {
      throw new MfaPushError(ERR.CHALLENGE_NOT_FOUND, `unknown challenge: ${challengeId}`);
    }
    return record;
  }

  _getUsable(challengeId) {
    const record = this._get(challengeId);
    this._refreshExpiry(record);
    if (record.state === STATES.EXPIRED) {
      throw new MfaPushError(ERR.EXPIRED, `challenge expired: ${challengeId}`);
    }
    if (record.state !== STATES.PENDING) {
      throw new MfaPushError(ERR.INVALID_STATE, `challenge not pending (state: ${record.state})`);
    }
    return record;
  }

  _refreshExpiry(record) {
    if (record.state === STATES.PENDING && record.expiresAt <= this._now()) {
      record.state = STATES.EXPIRED;
    }
  }

  _assertDevice(record, deviceKey) {
    if (typeof deviceKey !== 'string' || !timingSafeEqualStr(record.deviceKey, deviceKey)) {
      throw new MfaPushError(ERR.DEVICE_MISMATCH, 'approval does not come from the bound device');
    }
  }

  _assertAction(record, actionDigest) {
    if (typeof actionDigest !== 'string' || !timingSafeEqualStr(record.actionDigest, actionDigest)) {
      throw new MfaPushError(ERR.ACTION_MISMATCH, 'action digest does not match the original request');
    }
  }

  _assertNonce(record, nonce) {
    if (typeof nonce !== 'string' || !timingSafeEqualStr(record.nonce, nonce)) {
      throw new MfaPushError(ERR.NONCE_MISMATCH, 'nonce does not match the challenge');
    }
  }

  _assertSignature(record, { deviceKey, actionDigest, nonce, signature, decision }) {
    const expected = signApproval(deviceKey, {
      challengeId: record.challengeId,
      accountId: record.accountId,
      actionDigest: actionDigest || record.actionDigest,
      nonce: nonce || record.nonce,
      decision,
    });
    if (typeof signature !== 'string' || !timingSafeEqualStr(expected, signature)) {
      throw new MfaPushError(ERR.BAD_SIGNATURE, 'approval signature verification failed');
    }
  }

  _nonceUsed(accountId, nonce) {
    const set = this._usedNoncesByAccount.get(accountId);
    return set ? set.has(nonce) : false;
  }

  _markNonceUsed(accountId, nonce) {
    let set = this._usedNoncesByAccount.get(accountId);
    if (!set) {
      set = new Set();
      this._usedNoncesByAccount.set(accountId, set);
    }
    set.add(nonce);
  }
}

module.exports = {
  MfaPushStateMachine,
  MfaPushError,
  STATES,
  ERR,
  signApproval,
  approvalPayload,
};

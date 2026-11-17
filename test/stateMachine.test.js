'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  MfaPushStateMachine,
  MfaPushError,
  STATES,
  ERR,
  signApproval,
} = require('../src/stateMachine.js');

function makeClock(start = 1_000_000) {
  let now = start;
  return {
    now: () => now,
    advance: (ms) => { now += ms; },
  };
}

function makeMachine() {
  const clock = makeClock();
  const sm = new MfaPushStateMachine({ now: clock.now });
  return { sm, clock };
}

const BASE = {
  challengeId: 'ch-1',
  accountId: 'acct-1',
  deviceKey: 'device-secret-A',
  actionDigest: 'sha256:login:web:session-9',
  nonce: 'nonce-1',
};

function createChallenge(sm, overrides = {}) {
  return sm.createChallenge({ ...BASE, expiresAt: 1_000_000 + 60_000, ...overrides });
}

function approvalFor(fields, deviceKey = BASE.deviceKey) {
  return signApproval(deviceKey, {
    challengeId: fields.challengeId || BASE.challengeId,
    accountId: fields.accountId || BASE.accountId,
    actionDigest: fields.actionDigest || BASE.actionDigest,
    nonce: fields.nonce || BASE.nonce,
    decision: 'approve',
  });
}

function expectCode(code, fn) {
  assert.throws(fn, (err) => err instanceof MfaPushError && err.code === code);
}

test('happy path: pending -> approved -> consumed', () => {
  const { sm } = makeMachine();
  const created = createChallenge(sm);
  assert.equal(created.state, STATES.PENDING);

  const approved = sm.approve({
    challengeId: BASE.challengeId,
    deviceKey: BASE.deviceKey,
    actionDigest: BASE.actionDigest,
    nonce: BASE.nonce,
    signature: approvalFor({}),
  });
  assert.equal(approved.state, STATES.APPROVED);

  const consumed = sm.consume({
    challengeId: BASE.challengeId,
    deviceKey: BASE.deviceKey,
    actionDigest: BASE.actionDigest,
    nonce: BASE.nonce,
  });
  assert.equal(consumed.state, STATES.CONSUMED);
  assert.equal(sm.getState(BASE.challengeId), STATES.CONSUMED);
});

test('another device cannot approve the challenge', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  expectCode(ERR.DEVICE_MISMATCH, () =>
    sm.approve({
      challengeId: BASE.challengeId,
      deviceKey: 'attacker-device-key',
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
      signature: approvalFor({}, 'attacker-device-key'),
    })
  );
  assert.equal(sm.getState(BASE.challengeId), STATES.PENDING);
});

test('forged signature with the wrong key is rejected', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  expectCode(ERR.BAD_SIGNATURE, () =>
    sm.approve({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
      signature: approvalFor({}, 'some-other-key'),
    })
  );
});

test('changed action digest is rejected at approve and consume time', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  const tampered = 'sha256:login:web:session-EVIL';
  expectCode(ERR.ACTION_MISMATCH, () =>
    sm.approve({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: tampered,
      nonce: BASE.nonce,
      signature: approvalFor({ actionDigest: tampered }),
    })
  );

  sm.approve({
    challengeId: BASE.challengeId,
    deviceKey: BASE.deviceKey,
    actionDigest: BASE.actionDigest,
    nonce: BASE.nonce,
    signature: approvalFor({}),
  });
  expectCode(ERR.ACTION_MISMATCH, () =>
    sm.consume({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: tampered,
      nonce: BASE.nonce,
    })
  );
});

test('an approved challenge can only be consumed once', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  sm.approve({
    challengeId: BASE.challengeId,
    deviceKey: BASE.deviceKey,
    actionDigest: BASE.actionDigest,
    nonce: BASE.nonce,
    signature: approvalFor({}),
  });
  const consumeArgs = {
    challengeId: BASE.challengeId,
    deviceKey: BASE.deviceKey,
    actionDigest: BASE.actionDigest,
    nonce: BASE.nonce,
  };
  sm.consume(consumeArgs);
  expectCode(ERR.ALREADY_CONSUMED, () => sm.consume(consumeArgs));
});

test('concurrent approvals: exactly one wins', async () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  const attempt = () =>
    Promise.resolve().then(() =>
      sm.approve({
        challengeId: BASE.challengeId,
        deviceKey: BASE.deviceKey,
        actionDigest: BASE.actionDigest,
        nonce: BASE.nonce,
        signature: approvalFor({}),
      })
    );
  const results = await Promise.allSettled([attempt(), attempt(), attempt()]);
  const fulfilled = results.filter((r) => r.status === 'fulfilled');
  const rejected = results.filter((r) => r.status === 'rejected');
  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 2);
  for (const r of rejected) {
    assert.equal(r.reason.code, ERR.INVALID_STATE);
  }
  assert.equal(sm.getState(BASE.challengeId), STATES.APPROVED);
});

test('device rebind invalidates pending and approved challenges', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  createChallenge(sm, { challengeId: 'ch-2', nonce: 'nonce-2' });
  sm.approve({
    challengeId: 'ch-2',
    deviceKey: BASE.deviceKey,
    actionDigest: BASE.actionDigest,
    nonce: 'nonce-2',
    signature: approvalFor({ challengeId: 'ch-2', nonce: 'nonce-2' }),
  });

  const result = sm.rebindDevice({ accountId: BASE.accountId, newDeviceKey: 'device-secret-B' });
  assert.equal(result.invalidated, 2);
  assert.equal(sm.getState(BASE.challengeId), STATES.DENIED);
  assert.equal(sm.getState('ch-2'), STATES.DENIED);

  expectCode(ERR.INVALID_STATE, () =>
    sm.approve({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
      signature: approvalFor({}),
    })
  );
});

test('nonce replay across challenges is rejected', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  expectCode(ERR.NONCE_REPLAY, () =>
    createChallenge(sm, { challengeId: 'ch-2', nonce: BASE.nonce })
  );
});

test('wrong nonce on approval is rejected', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  expectCode(ERR.NONCE_MISMATCH, () =>
    sm.approve({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: 'nonce-other',
      signature: approvalFor({ nonce: 'nonce-other' }),
    })
  );
});

test('user cancel: deny moves to denied and blocks approve/consume', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  const denied = sm.deny({
    challengeId: BASE.challengeId,
    deviceKey: BASE.deviceKey,
    nonce: BASE.nonce,
    signature: signApproval(BASE.deviceKey, {
      challengeId: BASE.challengeId,
      accountId: BASE.accountId,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
      decision: 'deny',
    }),
  });
  assert.equal(denied.state, STATES.DENIED);
  expectCode(ERR.INVALID_STATE, () =>
    sm.approve({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
      signature: approvalFor({}),
    })
  );
  expectCode(ERR.INVALID_STATE, () =>
    sm.consume({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
    })
  );
});

test('deny from a different device is rejected', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  expectCode(ERR.DEVICE_MISMATCH, () =>
    sm.deny({
      challengeId: BASE.challengeId,
      deviceKey: 'attacker-device-key',
      nonce: BASE.nonce,
      signature: 'whatever',
    })
  );
  assert.equal(sm.getState(BASE.challengeId), STATES.PENDING);
});

test('timeout: expired challenge cannot be approved or consumed', () => {
  const { sm, clock } = makeMachine();
  createChallenge(sm);
  clock.advance(61_000);
  assert.equal(sm.getState(BASE.challengeId), STATES.EXPIRED);
  expectCode(ERR.EXPIRED, () =>
    sm.approve({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
      signature: approvalFor({}),
    })
  );
  expectCode(ERR.INVALID_STATE, () =>
    sm.consume({
      challengeId: BASE.challengeId,
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
    })
  );
});

test('sweep expires only overdue pending challenges', () => {
  const { sm, clock } = makeMachine();
  createChallenge(sm);
  createChallenge(sm, { challengeId: 'ch-2', nonce: 'nonce-2', expiresAt: 1_000_000 + 600_000 });
  clock.advance(61_000);
  assert.equal(sm.sweep(), 1);
  assert.equal(sm.getState(BASE.challengeId), STATES.EXPIRED);
  assert.equal(sm.getState('ch-2'), STATES.PENDING);
});

test('duplicate challenge id is rejected', () => {
  const { sm } = makeMachine();
  createChallenge(sm);
  expectCode(ERR.CHALLENGE_EXISTS, () => createChallenge(sm));
});

test('unknown challenge id is rejected', () => {
  const { sm } = makeMachine();
  expectCode(ERR.CHALLENGE_NOT_FOUND, () => sm.getState('nope'));
  expectCode(ERR.CHALLENGE_NOT_FOUND, () =>
    sm.consume({
      challengeId: 'nope',
      deviceKey: BASE.deviceKey,
      actionDigest: BASE.actionDigest,
      nonce: BASE.nonce,
    })
  );
});

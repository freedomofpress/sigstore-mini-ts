/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/**
 * Base class for all verification errors
 * Provides structured error handling with error codes
 */
export class VerificationError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = 'VerificationError';
    Object.setPrototypeOf(this, VerificationError.prototype);
  }
}

/**
 * Error thrown when timestamp verification fails
 */
export class TimestampError extends VerificationError {
  constructor(message: string) {
    super('TIMESTAMP_ERROR', message);
    this.name = 'TimestampError';
    Object.setPrototypeOf(this, TimestampError.prototype);
  }
}

/**
 * Error thrown when certificate verification fails
 */
export class CertificateError extends VerificationError {
  constructor(message: string) {
    super('CERTIFICATE_ERROR', message);
    this.name = 'CertificateError';
    Object.setPrototypeOf(this, CertificateError.prototype);
  }
}

/**
 * Error thrown when transparency log verification fails
 */
export class TLogError extends VerificationError {
  constructor(message: string) {
    super('TLOG_ERROR', message);
    this.name = 'TLogError';
    Object.setPrototypeOf(this, TLogError.prototype);
  }
}

/**
 * Error thrown when signature verification fails
 */
export class SignatureError extends VerificationError {
  constructor(message: string) {
    super('SIGNATURE_ERROR', message);
    this.name = 'SignatureError';
    Object.setPrototypeOf(this, SignatureError.prototype);
  }
}

/**
 * Error thrown when policy verification fails
 */
export class PolicyError extends VerificationError {
  constructor(message: string) {
    super('POLICY_ERROR', message);
    this.name = 'PolicyError';
    Object.setPrototypeOf(this, PolicyError.prototype);
  }
}

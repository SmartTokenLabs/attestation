/**
 * @jest-environment jsdom
 */

import {suite, test} from '@testdeck/mocha';
import {DEFAULT_VALIDITY_IN_MS, IUnpredictableNumberTool} from "./IUnpredictableNumberTool";
import {UNMac} from "./UNMac";
import {UNSignature} from "./UNSignature";
import {UnpredictableNumberBundle} from "./UnpredictableNumberBundle";
import {expect} from 'chai';
import { readFileSync } from 'fs';
import { KeyPair } from './KeyPair';


@suite
class UnpredictableNumberToolTest {

  static readonly DOMAIN: string = 'http://www.hotel-bogota.com';
  static readonly macKey: Uint8Array = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  static readonly PREFIX_PATH = '../../../../build/test-results/';
  static readonly attestorPubPEM = readFileSync(UnpredictableNumberToolTest.PREFIX_PATH + 'attestor-pub.pem', 'utf8');
  static readonly attestorPrivPEM = readFileSync(UnpredictableNumberToolTest.PREFIX_PATH + 'attestor-priv.pem', 'utf8');
  static readonly userPrivPEM = readFileSync(UnpredictableNumberToolTest.PREFIX_PATH + 'user-priv.pem', 'utf8');

  @test 'should be valid unpredictable number - mac'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("mac");
    expect(unt.domain).eq(UnpredictableNumberToolTest.DOMAIN);
    const un = unt.unpredictableNumberBundle;
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).true;
  }

  @test 'should be valid unpredictable number - sig'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("sig");
    expect(unt.domain).eq(UnpredictableNumberToolTest.DOMAIN);
    const un = unt.unpredictableNumberBundle;
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).true;
    // Validate in other instance with only public key
    const newUnt = new UNSignature(
      KeyPair.publicFromBase64orPEM(UnpredictableNumberToolTest.attestorPubPEM),
      UnpredictableNumberToolTest.DOMAIN,
      DEFAULT_VALIDITY_IN_MS);
    expect(newUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).true;
  }

  @test 'should throw error given invalid domain - mac'() {
    expect(
        () => new UNMac(UnpredictableNumberToolTest.macKey, 'NotADomain', BigInt(0))
    ).throw('Domain is not a valid domain');
  }

  @test 'should throw error given invalid domain - sig'() {
    expect(
        () => new UNSignature(KeyPair.privateFromPEM(UnpredictableNumberToolTest.attestorPrivPEM), 'NotADomain', BigInt(0))
    ).throw('Domain is not a valid domain');
  }

  @test 'should be invalid unpredictable number given invalid expiration - mac'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("mac");
    const un: UnpredictableNumberBundle = unt.unpredictableNumberBundle;
    un.expiration = BigInt(Date.now() - 1);
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid unpredictable number given invalid expiration - sig'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("sig");
    const un: UnpredictableNumberBundle = unt.unpredictableNumberBundle;
    un.expiration = BigInt(Date.now() - 1);
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid unpredictable number given different domain - mac'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("mac");
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: IUnpredictableNumberTool = new UNMac(
        UnpredictableNumberToolTest.macKey,
        'http://www.other-domain.com',
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid unpredictable number given different domain - sig'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("sig");
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: IUnpredictableNumberTool = new UNSignature(
        KeyPair.privateFromPEM(UnpredictableNumberToolTest.attestorPrivPEM),
        'http://www.other-domain.com',
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid predictable number given different key - mac'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("mac");
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: IUnpredictableNumberTool = new UNMac(
        new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]),
        UnpredictableNumberToolTest.DOMAIN,
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid predictable number given different key - sig'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("sig");
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: IUnpredictableNumberTool = new UNSignature(
      KeyPair.privateFromPEM(UnpredictableNumberToolTest.userPrivPEM),
        UnpredictableNumberToolTest.DOMAIN,
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'validate legacy Java UN - mac'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("mac");
    let randomness = new Uint8Array([117, -106, -9, 48, 71, 18, -58, 36, -121, 69, 93, 120, -100, 100, -108, 104, -5, 67, 73, -36, -121, 79, -128, -128, -59, -119, -2, -86, -126, -36, 74, 117]);
    expect(unt.validateUnpredictableNumber("ABJ34us29mc=", randomness, BigInt(1977060911693))).true;
  }

  @test 'validate Java UN - sig'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("sig");
    let randomness = new Uint8Array([2, 20, 104, 2, -86, -111, 43, -91, -81, -111, 23, 86, -62, -36, 114, -71, 96, -54, 37, 83, 58, 65, 75, 20, -78, 71, -71, 92, 117, 71, -3, 10]);
    expect(unt.validateUnpredictableNumber("aAj2NNsh6hUOL80pkmAXtzqg_AIOe9xv6BDki8_YVxZjxgZzY2dou911KqziR39PsN8OatY6pld6RxRC5lkHuxw=", randomness, BigInt(33197957883719))).true;
  }

  private static createUnt(type:string): IUnpredictableNumberTool {
    if (type === "mac") {
      return new UNMac(
          UnpredictableNumberToolTest.macKey,
          UnpredictableNumberToolTest.DOMAIN,
          DEFAULT_VALIDITY_IN_MS
      );
    } else if (type === "sig") {
      return new UNSignature(
        KeyPair.privateFromPEM(UnpredictableNumberToolTest.attestorPrivPEM),
        UnpredictableNumberToolTest.DOMAIN,
        DEFAULT_VALIDITY_IN_MS
      );
    } else {
      throw new Error("unknown UN type");
    }

  }
}

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
  static readonly unPubPEM = readFileSync(UnpredictableNumberToolTest.PREFIX_PATH + 'un-pub.pem', 'utf8');
  static readonly unPrivPEM = readFileSync(UnpredictableNumberToolTest.PREFIX_PATH + 'un-priv.pem', 'utf8');
  static readonly otherPrivPEM = readFileSync(UnpredictableNumberToolTest.PREFIX_PATH + 'other-priv.pem', 'utf8');

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
      KeyPair.publicFromBase64orPEM(UnpredictableNumberToolTest.unPubPEM),
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
        () => new UNSignature(KeyPair.privateFromPEM(UnpredictableNumberToolTest.unPrivPEM), 'NotADomain', BigInt(0))
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
        KeyPair.privateFromPEM(UnpredictableNumberToolTest.unPrivPEM),
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
      KeyPair.privateFromPEM(UnpredictableNumberToolTest.otherPrivPEM),
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

  @test 'validate Java UN - mac'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("mac");
    let randomness = new Uint8Array([28, -66, -9, -85, 78, -90, -64, -121, -111, 14, 93, -46, 65, -27, 64, 43, 75, -104, -121, -64, -67, -16, 4, -96, 66, -93, 99, 69, -89, -97, 39, -67]);
    expect(unt.validateUnpredictableNumber("llzLl_elSTv_64uII9FZGg==", randomness, BigInt(33198034831702))).true;
  }

  @test 'validate Java UN - sig'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("sig");
    let randomness = new Uint8Array([28, -66, -9, -85, 78, -90, -64, -121, -111, 14, 93, -46, 65, -27, 64, 43, 75, -104, -121, -64, -67, -16, 4, -96, 66, -93, 99, 69, -89, -97, 39, -67]);
    expect(unt.validateUnpredictableNumber("_GolZUnrFVhEzPbsXWPmgerc7FEblODjo4QW7lyLXo8kx4rhFFB5mpb5BFJL2m7BA8l1XIxLP6VuSswdqMgcsRw=", randomness, BigInt(33198026592589))).true;
  }

  @test 'validate Java UN context - mac'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("mac");
    let randomness = new Uint8Array([28, -66, -9, -85, 78, -90, -64, -121, -111, 14, 93, -46, 65, -27, 64, 43, 75, -104, -121, -64, -67, -16, 4, -96, 66, -93, 99, 69, -89, -97, 39, -67]);
    expect(unt.validateUnpredictableNumber("mMfnOhRXj5iNz6_L-n3cOw==", randomness, BigInt(33198026955780), new Uint8Array([42]))).true;
  }

  @test 'validate Java UN context - sig'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createUnt("sig");
    let randomness = new Uint8Array([28, -66, -9, -85, 78, -90, -64, -121, -111, 14, 93, -46, 65, -27, 64, 43, 75, -104, -121, -64, -67, -16, 4, -96, 66, -93, 99, 69, -89, -97, 39, -67]);
    expect(unt.validateUnpredictableNumber("hOiZ0Zxmvk1nP9JMNOM1zs7MoCFyeSvABc7Yh0bC6w8S3NcvgSuZS5SAWiqSYYe0vf5TF9OujCKgaCMDWJTryRw=", randomness, BigInt(33198027828689), new Uint8Array([42]))).true;
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
        KeyPair.privateFromPEM(UnpredictableNumberToolTest.unPrivPEM),
        UnpredictableNumberToolTest.DOMAIN,
        DEFAULT_VALIDITY_IN_MS
      );
    } else {
      throw new Error("unknown UN type");
    }

  }
}

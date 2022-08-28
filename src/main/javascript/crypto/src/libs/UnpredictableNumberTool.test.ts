/**
 * @jest-environment jsdom
 */

import {suite, test} from '@testdeck/mocha';
import {DEFAULT_VALIDITY_IN_MS, IUnpredictableNumberTool} from "./IUnpredictableNumberTool";
import {UNMac} from "./UNMac";
import {UnpredictableNumberBundle} from "./UnpredictableNumberBundle";
import {expect} from 'chai';


@suite
class UnpredictableNumberToolTest {

  static readonly DOMAIN: string = 'http://www.hotel-bogota.com';
  static readonly macKey: Uint8Array = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

  @test 'should be valid unpredictable number'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    expect(unt.domain).eq(UnpredictableNumberToolTest.DOMAIN);
    const un = unt.unpredictableNumberBundle;
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).true;
  }

  @test 'should throw error given invalid domain'() {
    expect(
        () => new UNMac(UnpredictableNumberToolTest.macKey, 'NotADomain', BigInt(0))
    ).throw('Domain is not a valid domain');
  }

  @test 'should be invalid unpredictable number given invalid expiration'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    const un: UnpredictableNumberBundle = unt.unpredictableNumberBundle;
    un.expiration = BigInt(0);
    expect(unt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid unpredictable number given different domain'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: IUnpredictableNumberTool = new UNMac(
        UnpredictableNumberToolTest.macKey,
        'http://www.other-domain.com',
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'should be invalid predictable number given different key'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    const un = unt.unpredictableNumberBundle;
    const differentDomainUnt: IUnpredictableNumberTool = new UNMac(
        new Uint8Array([8, 7, 6, 5, 4, 3, 2, 1]),
        UnpredictableNumberToolTest.DOMAIN,
        DEFAULT_VALIDITY_IN_MS
    );
    expect(differentDomainUnt.validateUnpredictableNumber(un.number, un.randomness, un.expiration)).false;
  }

  @test 'validate legacy Java UN'() {
    const unt: IUnpredictableNumberTool = UnpredictableNumberToolTest.createDefaultUnt();
    let randomness = new Uint8Array([117, -106, -9, 48, 71, 18, -58, 36, -121, 69, 93, 120, -100, 100, -108, 104, -5, 67, 73, -36, -121, 79, -128, -128, -59, -119, -2, -86, -126, -36, 74, 117]);
    expect(unt.validateUnpredictableNumber("ABJ34us29mc=", randomness, BigInt(1977060911693))).true;
  }

  private static createDefaultUnt(): IUnpredictableNumberTool {
    return new UNMac(
        UnpredictableNumberToolTest.macKey,
        UnpredictableNumberToolTest.DOMAIN,
        BigInt(10*365*24*3600*1000)
    );
  }
}

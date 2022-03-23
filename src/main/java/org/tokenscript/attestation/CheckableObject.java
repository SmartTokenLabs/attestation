package org.tokenscript.attestation;

import org.tokenscript.attestation.core.ASNEncodable;
import org.tokenscript.attestation.core.Validateable;
import org.tokenscript.attestation.core.Verifiable;

/**
 * Interface consolidating ASNEncodable, Verifiable, Validateable which is needed to make multiple interfaces play nicely with generics
 */
public interface CheckableObject extends ASNEncodable, Verifiable, Validateable {
}

//go:build windows

package main

import "testing"

func TestEquivalentSACLNormalisesOnlyProviderMetadata(t *testing.T) {
	absent := mustParseSACL(t, "")
	emptyAutoInherited := mustParseSACL(t, "S:AI")
	nullUnprotected := mustParseSACL(t, "S:NO_ACCESS_CONTROL")
	nullProtected := mustParseSACL(t, "S:PAINO_ACCESS_CONTROL")
	applied := mustParseSACL(t, "S:(AU;OICISA;CC;;;WD)")
	appliedAutoInherited := mustParseSACL(t, "S:AI(AU;OICISA;CC;;;WD)")
	appliedAutoRequested := mustParseSACL(t, "S:ARAI(AU;OICISA;CC;;;WD)")
	changedMask := mustParseSACL(t, "S:AI(AU;OICISA;DC;;;WD)")
	protected := mustParseSACL(t, "S:PAI(AU;OICISA;CC;;;WD)")
	ordered := mustParseSACL(t, "S:(AU;SA;CC;;;WD)(AU;SA;CC;;;SY)")
	reordered := mustParseSACL(t, "S:(AU;SA;CC;;;SY)(AU;SA;CC;;;WD)")

	if !equivalentSACL(absent, emptyAutoInherited) {
		t.Error("an absent and an empty unprotected SACL should be equivalent")
	}
	if !equivalentSACL(absent, nullUnprotected) || !equivalentSACL(nullUnprotected, absent) {
		t.Error("absent and null unprotected SACLs should be equivalent in either comparison order")
	}
	if !equivalentSACL(emptyAutoInherited, nullUnprotected) {
		t.Error("empty and null unprotected SACLs should be equivalent")
	}
	if equivalentSACL(absent, nullProtected) {
		t.Error("an absent SACL must not equal a protected null SACL")
	}
	emptyProtected := mustParseSACL(t, "S:P")
	if equivalentSACL(emptyProtected, nullProtected) {
		t.Error("a protected null SACL must not equal a protected valid empty SACL")
	}
	if !equivalentSACL(applied, appliedAutoInherited) {
		t.Error("AI is provider-managed and should not make equal ACEs differ")
	}
	if !equivalentSACL(applied, appliedAutoRequested) {
		t.Error("AR/AI are provider-managed and should not make equal ACEs differ")
	}
	if equivalentSACL(applied, changedMask) {
		t.Error("a changed audit access mask must not compare equal")
	}
	if equivalentSACL(applied, protected) {
		t.Error("a changed SACL protection state must not compare equal")
	}
	if equivalentSACL(ordered, reordered) {
		t.Error("a changed ACE order must not compare equal")
	}
}

func mustParseSACL(t *testing.T, sddl string) saclState {
	t.Helper()
	state, err := parseSACLState(sddl)
	if err != nil {
		t.Fatalf("parse %q: %v", sddl, err)
	}
	return state
}

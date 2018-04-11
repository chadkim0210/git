#!/bin/sh

gpg_version=$(gpg --version 2>&1)
if test $? != 127
then
	# As said here: http://www.gnupg.org/documentation/faqs.html#q6.19
	# the gpg version 1.0.6 didn't parse trust packets correctly, so for
	# that version, creation of signed tags using the generated key fails.
	case "$gpg_version" in
	'gpg (GnuPG) 1.0.6'*)
		say "Your version of gpg (1.0.6) is too buggy for testing"
		;;
	*)
		# Available key info:
		# * Type DSA and Elgamal, size 2048 bits, no expiration date,
		#   name and email: C O Mitter <committer@example.com>
		# * Type RSA, size 2048 bits, no expiration date,
		#   name and email: Eris Discordia <discord@example.net>
		# No password given, to enable non-interactive operation.
		# To generate new key:
		#	gpg --homedir /tmp/gpghome --gen-key
		# To write armored exported key to keyring:
		#	gpg --homedir /tmp/gpghome --export-secret-keys \
		#		--armor 0xDEADBEEF >> lib-gpg/keyring.gpg
		#	gpg --homedir /tmp/gpghome --export \
		#		--armor 0xDEADBEEF >> lib-gpg/keyring.gpg
		# To export ownertrust:
		#	gpg --homedir /tmp/gpghome --export-ownertrust \
		#		> lib-gpg/ownertrust
		mkdir ./gpghome &&
		chmod 0700 ./gpghome &&
		GNUPGHOME="$(pwd)/gpghome" &&
		export GNUPGHOME &&
		(gpgconf --kill gpg-agent >/dev/null 2>&1 || : ) &&
		gpg --homedir "${GNUPGHOME}" 2>/dev/null --import \
			"$TEST_DIRECTORY"/lib-gpg/keyring.gpg &&
		gpg --homedir "${GNUPGHOME}" 2>/dev/null --import-ownertrust \
			"$TEST_DIRECTORY"/lib-gpg/ownertrust &&
		gpg --homedir "${GNUPGHOME}" </dev/null >/dev/null 2>&1 \
			--sign -u committer@example.com &&
		test_set_prereq GPG
		;;
	esac
fi

if test_have_prereq GPG &&
    echo | gpg --homedir "${GNUPGHOME}" -b --rfc1991 >/dev/null 2>&1
then
	test_set_prereq RFC1991
fi

sanitize_pgp() {
	perl -ne '
		/^-----END PGP/ and $in_pgp = 0;
		print unless $in_pgp;
		/^-----BEGIN PGP/ and $in_pgp = 1;
	'
}

create_fake_signer () {
	write_script fake-signer <<-\EOF
	if [ "$1 $2" = "--status-fd=2 -bsau" ]; then
		echo >&2 "[GNUPG:] BEGIN_SIGNING"
		echo >&2 "[GNUPG:] SIG_CREATED D 1 SHA256 0 1513792449 4A7FF9E2330D22B19213A4E9E9C423BE17EFEE70"
		# avoid "-" in echo arguments
		printf "%s\n" \
		  "-----BEGIN FAKE SIGNER SIGNATURE-----" \
		  "fake-signature" \
		  "-----END FAKE SIGNER SIGNATURE-----"
		exit 0

	elif [ "$1 $2 $3" = "--status-fd=1 --keyid-format=long --verify" ]; then
		echo "[GNUPG:] NEWSIG"
		echo "[GNUPG:] GOODSIG 4A7FF9E2330D22B19213A4E9E9C423BE17EFEE70 /CN=Some User/EMail=some@user.email"
		echo "[GNUPG:] TRUST_FULLY 0 shell"
		echo >&2 "Good signature from /CN=Some User/EMail=some@user.email"
		exit 0

	else
		echo "bad arguments" 1>&2
		exit 1
	fi
	EOF
}

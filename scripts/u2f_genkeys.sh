#!/bin/bash
set -e

cat > u2f_keys.h <<EOF
#ifndef __U2F_KEYS_H_INCLUDED__
#define __U2F_KEYS_H_INCLUDED__

#include <stdint.h>

const uint8_t U2F_ATT_PRIV_KEY[] = {
EOF

if [ \! -e keepkeydevkey.pem ]; then
    openssl ecparam -genkey -out keepkeydevkey.pem -name prime256v1
fi
openssl ec -in keepkeydevkey.pem -text  |
    perl -e '$key = "\t"; while (<>) {
      if (/priv:/) { $priv = 1 }
      elsif (/pub:/) { $priv = 0 }
      elsif ($priv) {
        while ($_ =~ s/.*?([0-9a-f]{2})//) {
          $key .= "0x$1,";
          if ($num++ % 8 == 7) { $key .= "\n\t"; }
          else {$key .= " ";}
        }
      }
    }
    $key =~ s/,\s*$/\n/s;
    print $key;' >> u2f_keys.h
cat >> u2f_keys.h <<EOF
};

const uint8_t U2F_ATT_CERT[] = {
EOF

openssl req -new -key keepkeydevkey.pem -out keepkeydevcert.req -subj "/CN=KeepKey U2F"
openssl x509 -req -in keepkeydevcert.req -signkey keepkeydevkey.pem -days 3650 -out keepkeydevcert.pem
openssl x509 -in keepkeydevcert.pem -outform der | xxd
#| od -tx1 -w12 -Anone | perl -pe 's/ ([0-9a-f]{2})/ 0x$1,/g; $_ =~ s/^ /\t/;' >> u2f_keys.h

cat >> u2f_keys.h <<EOF
};

#endif // __U2F_KEYS_H_INCLUDED__
EOF

rm keepkeydevcert.req keepkeydevcert.pem

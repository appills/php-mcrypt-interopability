# php-mcrypt-interopability
Tests for compatible cipher modes between php's ext-mcrypt and ext-openssl

# tl;dr

| mcrypt mode | openssl compatible? | openssl mode |
| ----------- | ------------------- | ------------ |
| ecb | yes | ecb |
| cbc | yes | cbc |
| cfb | yes | cfb8 |
| ncfb | yes | cfb |
| ctr | yes | ctr |
| nofb | yes | ofb |
| ofb | no | x |
| stream | ? | ? |

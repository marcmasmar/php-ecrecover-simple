# php-ecrecover-simple
A PHP file that conains the required procedures aimed to recover a signed message width personal_sign.
## Requires
- PHP
- GMP extension

## Using
```
require_once("ecrecover-simple.php");

$addr = \ECRecoverSimple\fromMessage(
    "Sign-In",
    "0xe4ad6b81ebd40bcd7420e95c7e5c88c64ba3fed80a06067078af7e0a9457f5a6728005fcab5d5abf80d5bed4bccae63338de0f0f369197d8dd12ee1b704c8ffe1c"
);

echo $addr;
```

## Features
The work in [wmh/php-ecrecover](https://gitbhub.com/wmh/php-ecrecover), [kornrunner/keccak](https://gitbhub.com/kornrunner/keccak) stripped down to only personal_sign recover.
Some features where optimized*, while Keccak improved significantly, curve function optimizations does not lead to improvements (yet).
- Keccak 10k runs  3.1  vs 2.0  seconds
- erecover 10k runs  8.4  vs 7.8 seconds
* Via GPT4 suggestions and unrolls.

## Credits
In case you liked it, make sure to credit referenced projects.

### My Eth account
```
0xe7D20412FeC151ac99864cFA7dc825999DCaC602
```


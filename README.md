# php-ecrecover-simple
A PHP file that conains the required procedures aimed to recover a signed message width personal_sign.
## Requires
- PHP
- GMP extension

## Using
```
require_once("ecrecover-simple.php");

$msg = "Sign-In";
$sign = filter_input(INPUT_GET, 'sign', FILTER_SANITIZE_STRING);

$addr = \PersonalRecover\fromMessage($msg,$sign);
echo $addr.EOL;
```

## Features
The work from Cr and Ke, plus its references, stripped down to only personal_sign recover.
Some features where optimized, while Keccak improved significantly, curve function optimizations does not lead to improvements (yet).
- Keccak 10k runs  3.1  vs 2.0  seconds
- erecover 10k runs  8.4  vs 7.8 seconds

## Credits
In case you liked it, make sure to credit referenced projects.

### My Eth account
```
0xe7D20412FeC151ac99864cFA7dc825999DCaC602
```


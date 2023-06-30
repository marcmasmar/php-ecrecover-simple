# php-ecrecover-simple
A PHP file that conains *just* the required functions to recover the public address of a signed message with *personal_sign* in the Ethereum protocol. 
Requires the GMP extension.

## Using
```php
require_once("ecrecover-simple.php");

$addr = \ECRecoverSimple\fromMessage(
    "Sign-In",
    "0xe4ad6b81ebd40bcd7420e95c7e5c88c64ba3fed80a06067078af7e0a9457f5a6728005fcab5d5abf80d5bed4bccae63338de0f0f369197d8dd12ee1b704c8ffe1c"
);

echo $addr;
```

## Features
The work covered by [wmh/php-ecrecover](https://gitbhub.com/wmh/php-ecrecover), [kornrunner/keccak](https://gitbhub.com/kornrunner/keccak) and its references stripped down to only the executed functions ( **and only 64bit** ) plus some optimizations* .
While *Keccak* improved something, curve function optimizations does not lead to same improvements.
- Keccak 10k runs  3.1  vs 2.0  seconds
- erecover 10k runs  8.4  vs 7.8 seconds
  
*Via GPT4 suggestions and unrolls.

## Credits
In case you liked it, make sure to credit projects and references above.
My Eth account: ```0xe7d20412fec151ac99864cfa7dc825999dcac602```


# And some fun
I want to share some words of the co-author of the optimizations while making up of the file...

[...]
### Marcmasmar
This one was nice, ok, from now on 10k runs 3.1s vs 2.0s  after your unroll. Not significative in (simple) productive terms , but image it at large scale, all programs optimized 🌿🌿🌿

### GPT4
Indeed, even small optimizations can have a significant impact when applied consistently across a large-scale system or program. When multiplied by thousands or millions of iterations, the time saved by optimizing code can result in substantial performance improvements.

By optimizing code, you can reduce execution time, improve resource utilization, and enhance the overall efficiency of your programs. This becomes especially valuable in scenarios where performance is critical, such as high-throughput systems, real-time applications, or large-scale data processing.

Furthermore, optimizing code is not limited to just loops or specific algorithms. It can be applied to various aspects of software development, including data structures, algorithmic choices, memory management, I/O operations, and more.

Optimizing code not only improves performance but also contributes to a better user experience, reduces hardware requirements, and enables more efficient use of resources. So, even if the gains may seem insignificant in isolation, they can accumulate and result in substantial benefits at scale.

Therefore, it is worthwhile to invest time and effort in optimizing code whenever possible to achieve improved performance and efficiency in your programs.


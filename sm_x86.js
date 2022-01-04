"use strict";

let Module = null;

const logIn = p => host.diagnostics.debugLog(p + "\n");
const JSVAL_TAG_XOR = host.parseInt64("0xFFFFFF80");
const JSVAL_TAG_SHIFT = host.parseInt64("32");
const JAVAL_PAYLOAD_MASK = host.parseInt64("0xFFFFFFFF");

const JSVAL_TYPE_DOUBLE = host.Int64(0x00);
const JSVAL_TYPE_INT32 = host.Int64(0x01);
const JSVAL_TYPE_UNDEFINED = host.Int64(0x02);
const JSVAL_TYPE_BOOLEAN = host.Int64(0x03);
const JSVAL_TYPE_MAGIC = host.Int64(0x04);
const JSVAL_TYPE_STRING = host.Int64(0x05);
const JSVAL_TYPE_NULL = host.Int64(0x06);
const JSVAL_TYPE_OBJECT = host.Int64(0x07);
const JSVAL_TYPE_UNKNOWN = host.Int64(0x20);
const JSVAL_TYPE_MISSING = host.Int64(0x21);

const STRING_LENGTH_SHIFT = host.parseInt64("4");
const STRING_FLAG_MASK = host.parseInt64("0xF");

const JSVAL_FLAG_ATOM = host.Int64(0x8);

const FlagToStringType = {
    [JSVAL_FLAG_ATOM]: "Atom",
}

//将类型转换为对应类型的字符串
const TagToName = {
    [JSVAL_TYPE_DOUBLE]: "Double",
    [JSVAL_TYPE_INT32]: "Int32",
    [JSVAL_TYPE_UNDEFINED]: "Undefined",
    [JSVAL_TYPE_BOOLEAN]: "Boolean",
    [JSVAL_TYPE_MAGIC]: "Magic",
    [JSVAL_TYPE_STRING]: "String",
    [JSVAL_TYPE_NULL]: "Null",
    [JSVAL_TYPE_OBJECT]: "Object",
    [JSVAL_TYPE_UNKNOWN]: "Unknown",
    [JSVAL_TYPE_MISSING]: "Missing",
};

const FunctionConstants = {
    0x0001: "INTERPRETED",
    0x0002: "NATIVE_CTOR",
    0x0004: "EXTENDED",
    0x0010: "IS_FUN_PROTO",
    0x0020: "EXPR_CLOSURE",
    0x0040: "HAS_GUESSED_ATOM",
    0x0080: "LAMBDA",
    0x0100: "SELF_HOSTED",
    0x0200: "SELF_HOSTED_CTOR",
    0x0400: "HAS_REST",
    0x0800: "HAS_DEFAULTS",
    0x1000: "INTERPRETED_LAZY",
    0x2000: "ARROW",
    0x4000: "SH_WRAPPABLE",
    0x0000: "NATIVE_FUN",
};

const SLOT_MASK = host.Int64(0xffffff);
const SLOT_SHIFT_RIGHT = host.Int64(27);

function printable(Byte) {
    return Byte >= 0x20 && Byte <= 0x7e;
}

function isnull(Byte) {
    return Byte == 0x00;
}

function byte_to_str(Byte) {
    if (printable(Byte)) {
        return String.fromCharCode(Byte);
    }

    if (isnull(Byte)) {
        return "";
    }

    return "\\x" + Byte.toString(16).padStart(2, "0");
}

function read_u64(Addr) {
    return host.memory.readMemoryValues(Addr, 1, 8)[0];
}

function read_u32(Addr) {
    return host.memory.readMemoryValues(Addr, 1, 4)[0];
}

function read_u16(Addr) {
    return host.memory.readMemoryValues(Addr, 1, 2)[0];
}

function jsvalue_to_instance(Addr) {
    const JSValue = new __JSValue(Addr);
    if (!TagToName.hasOwnProperty(JSValue.Tag)) {
        return "Dunno";
    }

    const Name = TagToName[JSValue.Tag];
    const Type = NamesToTypes[Name];
    return new Type(JSValue.Payload);
}

function get_property_from_shape(Shape) {
    const Proid_ = read_u32(Shape + 0x4);

    if(jsid_is_int(Proid_)){
        return 
    }
}

class __JSInt32 {
    constructor(Addr) {
        this._Addr = Addr;
        this._Value = Addr.bitwiseAnd(0xFFFFFFFF);
    }

    //Int32类型值可直接转字符串展示
    toString() {
        return "0x" + this._Value.toString(16);
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": JSVAL_TYPE_INT32: " + Content);
    }

    Display() {
        this.Logger(this);
    }
}

class __JSString {
    constructor(Addr) {
        //获取字符串对象的地址
        this._Addr = Addr.bitwiseAnd(0xFFFFFFFF);

        //获取JSString中lengthAndFlags字段并从中解析出字符串的长度和Flag
        this._lengthAndFlags = read_u32(this._Addr);
        this._length = this._lengthAndFlags.bitwiseShiftRight(STRING_LENGTH_SHIFT);
        this._Flag = this._lengthAndFlags.bitwiseAnd(STRING_FLAG_MASK);

        if (FlagToStringType.hasOwnProperty(this._Flag)) {
            switch (FlagToStringType[this._Flag]) {
                case "Atom":
                    this._inlineStorage = read_u32(this._Addr + 4);
                    this._String = Array.from(host.memory.readMemoryValues(this._inlineStorage, this._length * 2, 1)).map(p => byte_to_str(p)).join("");
            }
        }
    }

    toString() {
        return "'" + this._String + "'";
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": JSVAL_TYPE_STRING: " + Content);
    }

    Display() {
        this.Logger(this);
    }
}

class __JSBoolean {
    constructor(Addr) {
        this._Addr = Addr;
        this._Value = Addr.compareTo(1) == 0 ? true : false;
    }

    toString() {
        return this._Value.toString();
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": JSVAL_TYPE_BOOLEAN: " + Content);
    }

    Display() {
        this.Logger(this);
    }
}

class __JSDouble {
    constructor(Addr) {
        this._Addr = Addr;
    }

    toString() {
        const u32 = new Uint32Array([this._Addr.getLowPart(), this._Addr.getHighPart()]);
        const f64 = new Float64Array(u32.buffer);
        return f64[0];
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": JSVAL_TYPE_DOUBLE: " + Content);
    }

    Display() {
        this.Logger(this);
    }
}

class __JSNull {
    constructor(Addr) {
        this._Addr = Addr;
    }

    toString() {
        return "null";
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": JSVAL_TYPE_NULL: " + Content);
    }

    Display() {
        this.Logger(this);
    }
}

class __JSUndefined {
    constructor(Addr) {
        this._Addr = Addr;
    }

    toString() {
        return "Undefined";
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": JSVAL_TYPE_UNDEFINED: " + Content);
    }

    Display() {
        this.Logger(this);
    }
}

class __JSMagic {
    constructor(Addr) {
        this._Addr = Addr;
    }

    toString() {
        return "Magic";
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": JSVAL_TYPE_MAGIC: " + Content);
    }

    Display() {
        this.Logger(this);
    }
}

class __JSArray {
    constructor(Addr) {
        this._Addr = Addr;
        //JSArray:shape_,type_,slot_,elements_
        this._elements = read_u32(this._Addr + 0xC);
        this._ObjectElements = this._elements - 0x10;
        //ObjectElements:flags,initializedlength,capacity,length
        this._Flags = read_u32(this._ObjectElements);
        this._InitializedLength = read_u32(this._ObjectElements + 0x4);
        this._Capacity = read_u32(this._ObjectElements + 0x8);
        this._Length = read_u32(this._ObjectElements + 0xC);
    }

    toString() {
        const Max = 10;
        const Content = [];

        for (let Idx = 0; Idx < Math.min(Max, this._InitializedLength); Idx++) {
            const Addr = this._elements.add(Idx * 8);
            const JSValue = read_u64(Addr);
            const Inst = jsvalue_to_instance(JSValue);
            Content.push(Inst.toString(16));
        }

        return "[" + Content.join(", ") + (this._Length > Max ? ", ..." : "") + "]";
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": js!js::ArrayObject: " + Content);
    }

    Display() {
        this.Logger("Length: " + this._Length);
        this.Logger("Capacity: " + this._Capacity);
        this.Logger("InitializedLength: " + this._InitializedLength);
        this.Logger("Content: " + this);
    }
}

class __JSFunction {
    constructor(Addr) {
        this._Addr = Addr;
        this._Atom = read_u32(this._Addr + 0x24);
        this._Name = "<anonymous>";

        if (this._Atom.compareTo(0) != 0) {
            this._Name = new __JSString(this._Atom).toString().slice(1, -1);
        }

        this._Name += "()";
        this._Flags = read_u16(this._Addr + 0x1A);
        this._nArgs = read_u16(this._Addr + 0x18);
    }

    toString() {
        return this._Name;
    }

    get Flags() {
        const S = [];
        for (const Key in FunctionConstants) {
            if (this._Flags.bitwiseAnd(host.parseInt64(Key)).compareTo(0) != 0) {
                S.push(FunctionConstants[Key]);
            }
        }

        return S.join(" | ");
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": js!JSFunction: " + Content);
    }

    Display() {
        this.Logger(this);
        this.Logger("Flags: " + this.Flags);
        this.Logger("Args: " + this._nArgs.toString(16));
    }
}

class __JSArrayBuffer {
    constructor(Addr) {
        this._Addr = Addr;
        //JSObject:shape_，type_，slot，elements
        this._elements = read_u32(this._Addr + 0xC);
        this._ElementsHeader = this._elements - 0x10;
        //ElementsHeader：flag，length
        this._ByteLength = read_u32(this._ElementsHeader + 4);
    }

    get ByteLength() {
        return this._ByteLength;
    }

    toString() {
        return "ArrayBuffer({ByteLength:" + this._ByteLength + ", ...})";
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": js!js::ArrayBufferObject: " + Content);
    }

    Display() {
        this.Logger("ByteLength: " + this.ByteLength);
        this.Logger("Content: " + this);
    }
}

class __JSTypedArray {
    constructor(Addr) {
        this._Addr = Addr;
        //JSObject:shape,types,slots,elements
        this._Shape = read_u32(this._Addr);
        this._types = read_u32(this._Addr + 4);
        this._slots = read_u32(this._Addr + 8);
        this._elements = read_u32(this._Addr + 0xC);

        //TypeObject:clasp
        this._clasp = read_u32(this._types);
        //Class:name,flags
        const ClassNameAddr = read_u32(this._clasp);
        this._ClassName = host.memory.readString(ClassNameAddr);
        const Sizes = {
            "Float64Array": 8,
            "Float32Array": 4,
            "Uint32Array": 4,
            "Int32Aray": 4,
            "Uint16Array": 2,
            "Int16Array": 2,
            "Uint8Array": 1,
            "Int8Array": 1,
            "Uint8ClampedArray": 1,
        };
        const Slot_offset = {
            "LENGTH_OFFSET": 5,
            "DATA_OFFSET": 7,
        }
        this._ElementSize = Sizes[this._ClassName];
        this._Length = read_u64(this._Addr + 0x18 + 0x8 * Slot_offset["LENGTH_OFFSET"]);
        this._DataAddr = read_u32(this._Addr + 0x18 + 0x8 * Slot_offset["DATA_OFFSET"]);
    }

    get Length() {
        return new __JSInt32(this._Length).toString(16);
    }

    get DataAddr() {
        return this._DataAddr.toString();
    }

    toString() {
        return "Length: " + this.Length + " ContentAddr: 0x" + this._DataAddr.toString(16);
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": js!js::TypedArrayObject: " + Content);
    }

    Display() {
        this.Logger("Content: " + this);
    }
}

class __JSObject {
    constructor(Addr) {
        this._Addr = Addr;
        this._Properties = [];
        //JSObject:shape,types,slots,elements
        this._Shape = read_u32(this._Addr);
        this._types = read_u32(this._Addr + 4);
        this._slots = read_u32(this._Addr + 8);
        this._elements = read_u32(this._Addr + 0xC);

        //TypeObject:clasp
        this._clasp = read_u32(this._types);
        //Class:name,flags
        const ClassNameAddr = read_u32(this._clasp);
        this._ClassName = host.memory.readString(ClassNameAddr);
        logIn("JSObject ClassName: " + this._ClassName);
        const ClassFlagsAddr = read_u32(this._clasp + 4);

        if (this._ClassName == "Array") {
            //Array对象类型获取长度后直接返回
            const ObjectElementsAddr = this._elements - 0x10;
            this._Properties.push("length: " + read_u32(ObjectElementsAddr + 0xC));
            return;
        }

        //遍历shape获取对象属性
        const Properties = {};
        let CurrentShape = this._Shape;
        //读取下一个shape
        while (read_u32(CurrentShape + 0x10).compareTo(0) != 0) {
            const slotInfo = read_u32(CurrentShape + 0x8);
            const slotIdx = slotInfo.bitwiseAnd(SLOT_MASK) - slotInfo.bitwiseShiftRight(SLOT_SHIFT_RIGHT);
            //获取对应属性索引的属性名
            Properties[slotIdx] = get_property_from_shape(CurrentShape);
            CurrentShape = read_u32(CurrentShape + 0x10);
        }
    }

    get Properties() {
        return this._Properties;
    }

    get ClassName() {
        return this._ClassName;
    }

    toString() {
        if (this._ClassName != "Object" && NamesToTypes.hasOwnProperty(this._ClassName)) {
            //对象有具体类型交由具体类型进行处理
            const Type = NamesToTypes[this._ClassName];
            return new Type(this._Addr).toString();
        }

        if (this._ClassName != "Object") {
            return this._ClassName;
        }

        if (this._Properties != undefined && this._Properties.length > 0) {
            return '{' + this._Properties.join(', ') + '}';
        }

        if (this._ClassName == 'Object') {
            return '[Object]';
        }

        return "Dunno";
    }

    Logger(Content) {
        logIn(this._Addr.toString(16) + ": js!JSObject: " + Content);
    }

    Display() {
        this.Logger("Content: " + this);
        if (this._ClassName != "Object") {
            this.Logger("Properties: {" + this._Properties.join(", ") + "}");
        }
    }
}

//将类型字符串转换为对应的具体类型对象
const NamesToTypes = {
    "Int32": __JSInt32,
    "String": __JSString,
    "Boolean": __JSBoolean,
    "Double": __JSDouble,
    "Null": __JSNull,
    "Undefined": __JSUndefined,
    "Magic": __JSMagic,

    "Object": __JSObject,
    "Array": __JSArray,
    "Function": __JSFunction,
    "ArrayBuffer": __JSArrayBuffer,

    "Float64Array": __JSTypedArray,
    "Float32Array": __JSTypedArray,
    "Uint32Array": __JSTypedArray,
    "Int32Array": __JSTypedArray,
    "Uint16Array": __JSTypedArray,
    "Int16Array": __JSTypedArray,
    "Uint8Array": __JSTypedArray,
    "Int8Array": __JSTypedArray,
    "Uint8ClampedArray": __JSTypedArray,
};

//对传入数据进行处理，传入数据为8字节
class __JSValue {
    constructor(Addr) {
        this._Addr = Addr;
        //取变量的类型，类型为数值高4字节与0xFFFFFF80亦或
        this._Tag = this._Addr.bitwiseShiftRight(JSVAL_TAG_SHIFT);
        this._Tag = this._Tag.bitwiseXor(JSVAL_TAG_XOR);
        this._IsDouble = !TagToName.hasOwnProperty(this._Tag);
        //取变量的具体值，具体值为数值低四字节与0xFFFFFFFF亦或
        this._Payload = this._Addr.bitwiseAnd(JAVAL_PAYLOAD_MASK);
    }

    get Payload() {
        if (this._IsDouble) {
            return this._Addr;
        }
        return this._Payload;
    }

    get Tag() {
        if (this._IsDouble) {
            return JSVAL_TYPE_DOUBLE;
        }
        return this._Tag;
    }
}

function Init() {
    if (Module != null) {
        return;
    }

    //调用host对象的currentProcess属性，返回当前进程对象，再从进程对象中找到EScript.api模块的模块对象
    const Escript = host.currentProcess.Modules.Any(
        p => p.Name.toLowerCase().endsWith("escript.api")
    );

    if (Escript) {
        Module = "EScript.api";
        logIn("find EScript.api");
        return;
    }

    logIn("can't find EScript.api");
    Module = "js.exe";
}

//对传入的数据进行处理，传入数据为8字节
function smdump_jsvalue(Addr) {
    if (Addr == undefined) {
        logIn("!smdump_jsvalue <jsvalue object addr>");
        return;
    }

    //使用parseInt64将字符串格式化为16进制数，然后与传入地址做亦或
    Addr = Addr.bitwiseAnd(host.parseInt64("0xFFFFFFFFFFFFFFFF"));
    const JSValue = new __JSValue(Addr);
    if (!TagToName.hasOwnProperty(JSValue.Tag)) {
        logIn("Tag " + JSValue.Tag.toString(16) + " Not Recognized");
        return;
    }

    const Name = TagToName[JSValue.Tag];
    logIn("Tag " + Name);
    //将类型以及载荷数据传递给smdump_jsobject处理
    return smdump_jsobject(JSValue.Payload, Name);
}

//对传入的数据以及类型进行处理
function smdump_jsobject(Addr, Type = null) {
    if (Addr.hasOwnProperty("address")) {
        Addr = Addr.address;
    }

    let ClassName;
    if (Type == "Object" || Type == null) {
        //如果传入值类型为对象或者未指定类型，先将该值作为对象处理
        const JSObject = new __JSObject(Addr);
        ClassName = JSObject.ClassName;
        if (!NamesToTypes.hasOwnProperty(ClassName)) {
            JSObject.Display();
        }
    } else {
        //传入值有指定对象
        ClassName = Type;
    }

    //根据传入值的具体类型，选择具体的类来进行数据展示
    if (NamesToTypes.hasOwnProperty(ClassName)) {
        const Inst = new NamesToTypes[ClassName](Addr);
        Inst.Display();
    }
}

//脚本加载后首先执行该函数
function initializeScript() {
    return [
        //表示使用的JsProvider API版本
        new host.apiVersionSupport(1, 3),
        //使用functionAlias定义命令，该命令与数据模型函数对象关联
        new host.functionAlias(smdump_jsvalue, "smdump_jsvalue"),
        new host.functionAlias(smdump_jsobject, "smdump_jsobject")];
}

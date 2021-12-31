"use strict";

let Module = null;

const logIn = p => host.diagnostics.debugLog(p + '\n');
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
        this._lengthAndFlags = host.memory.readMemoryValues(this._Addr, 1, 4)[0];
        this._length = this._lengthAndFlags.bitwiseShiftRight(STRING_LENGTH_SHIFT);
        this._Flag = this._lengthAndFlags.bitwiseAnd(STRING_FLAG_MASK);

        if (FlagToStringType.hasOwnProperty(this._Flag)) {
            switch (FlagToStringType[this._Flag]) {
                case "Atom":
                    this._inlineStorage = host.memory.readMemoryValues(this._Addr + 4, 1, 4)[0];
                    this._String = Array.from(host.memory.readMemoryValues(this._inlineStorage, this._length * 2, 1)).map(p => byte_to_str(p)).join('');
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
        logIn(this._Addr.toString(16) + ': JSVAL_TYPE_BOOLEAN: ' + Content);
    }

    Display() {
        this.Logger(this);
    }
}

//将类型字符串转换为对应的具体类型对象
const NamesToTypes = {
    "Int32": __JSInt32,
    "String": __JSString,
    "Boolean": __JSBoolean,
};

class __JSValue {
    constructor(Addr) {
        this._Addr = Addr;
        //取变量的类型，类型为数值高4字节与0xFFFFFF80亦或
        this._Tag = this._Addr.bitwiseShiftRight(JSVAL_TAG_SHIFT);
        this._Tag = this._Tag.bitwiseXor(JSVAL_TAG_XOR);
        this._IsDouble = this._Tag.compareTo(JSVAL_TYPE_DOUBLE) < 0;
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

function smdump_jsvalue(Addr) {
    if (Addr == undefined) {
        logIn("!smdump_jsvalue <jsvalue object addr>");
        return;
    }

    //使用parseInt64将字符串格式化为16进制数，然后与传入地址做亦或
    Addr = Addr.bitwiseAnd(host.parseInt64('0xFFFFFFFFFFFFFFFF'));
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

function smdump_jsobject(Addr, Type = null) {
    if (Addr.hasOwnProperty("address")) {
        Addr = Addr.address;
    }

    let ClassName;
    if (Type == "Object" || Type == null) {
        //如果传入值类型为对象或者未指定类型，先将该值作为对象处理
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
import { OsType, PortProtocol } from "../../api/generated";
import {
    ASTField,
    ASTFields,
    ASTResult,
    DomainAST,
    Expr,
    GlobalAST,
    HostAST,
    HttpServiceAST,
    PortAST,
    ServiceAST,
} from "./ast";
import { Cursor } from "./cursor";
import ParserError from "./error";
import { tokenize } from "./lexer";

/**
 * Parse a string into a generic AST defined in {@link ASTFields}. This is the
 * implementation function for `parse{Global,Domain,Host,etc}AST`
 *
 * @param input the whole filter string.
 * @param ast the AST from ast.ts including the columns with their types to parse.
 *
 * @throws ParserError
 *
 * @returns the parsed AST for generic filter string.
 */
export function parseAstFields<Fields extends ASTField>(input: string, ast: Fields): ASTResult<Fields> {
    // create object like `{ tags: [], createdAt: [], ... }`
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const ret = Object.fromEntries(Object.keys(ast).map((k) => [k, [] as any[]])) as {
        [Key in keyof Fields]: Array<Expr.Or<ReturnType<Fields[Key]["parse"]>>>;
    };

    parseAst(input, (column, cursor) => {
        const field = Object.keys(ast).find((field) => ast[field].columns.includes(column)) as keyof Fields;
        if (!field) throw new ParserError({ type: "unknownColumn", column });
        ret[field].push(parseOr(cursor, ast[field].parse));
    });
    return ret;
}

/**
 * Parse a string into a {@link GlobalAST}
 *
 * @param input the whole filter string.
 *
 * @throws ParserError
 *
 * @returns the parsed AST for global filters.
 */
export function parseGlobalAST(input: string): GlobalAST {
    return parseAstFields(input, ASTFields.global);
}

/**
 * Parse a string into a {@link DomainAST}
 *
 * @param input the whole filter string.
 *
 * @throws ParserError
 *
 * @returns the parsed AST for domain filters.
 */
export function parseDomainAST(input: string): DomainAST {
    return parseAstFields(input, ASTFields.domain);
}

/**
 * Parse a string into a {@link HostAST}
 *
 * @param input the whole filter string.
 *
 * @throws ParserError
 *
 * @returns the parsed AST for host filters.
 */
export function parseHostAST(input: string): HostAST {
    return parseAstFields(input, ASTFields.host);
}

/**
 * Parse a string into a {@link PortAST}
 *
 * @param input the whole filter string.
 *
 * @throws ParserError
 *
 * @returns the parsed AST for port filters.
 */
export function parsePortAST(input: string): PortAST {
    return parseAstFields(input, ASTFields.port);
}

/**
 * Parse a string into a {@link ServiceAST}
 *
 * @param input the whole filter string.
 *
 * @throws ParserError
 *
 * @returns the parsed AST for service filters.
 */
export function parseServiceAST(input: string): ServiceAST {
    return parseAstFields(input, ASTFields.service);
}

/**
 * Parse a string into a {@link HttpServiceAST}
 *
 * @param input the whole filter string.
 *
 * @throws ParserError
 *
 * @returns the parsed AST for http service filters.
 */
export function parseHttpServiceAST(input: string): HttpServiceAST {
    return parseAstFields(input, ASTFields.httpService);
}

/**
 * Helper function to be called from `parse...AST`
 *
 * @param input the source string to parse
 * @param parseColumn is a callback which is invoked with each column which is encountered.
 *     Its arguments are the column's name and the cursor to parse the column's expression.
 */
function parseAst(input: string, parseColumn: (column: string, cursor: Cursor) => void) {
    const tokens = tokenize(input);
    const cursor = new Cursor(tokens);
    for (;;) {
        const token = cursor.nextToken();
        if (token === null) break;

        if (token.type === "column") parseColumn(token.value, cursor);
        else throw new ParserError({ type: "unexpectedToken", exp: "column", got: token });
    }
}

/** Parse an {@link Expr.Or} expression using a `parseValue` to parse the leaves */
function parseOr<T>(tokens: Cursor, parseValue: (cursor: Cursor) => Expr.Value<T>): Expr.Or<T> {
    const list = [parseAnd(tokens, parseValue)];
    while (tokens.peekToken()?.type === "logicalOr") {
        tokens.nextToken(); // Consume the `,`
        list.push(parseAnd(tokens, parseValue));
    }
    return { or: list };
}

/** Parse an {@link Expr.And} expression using a `parseValue` to parse the leaves */
function parseAnd<T>(tokens: Cursor, parseValue: (cursor: Cursor) => Expr.Value<T>): Expr.And<T> {
    const list = [parseNot(tokens, parseValue)];
    while (tokens.peekToken()?.type === "logicalAnd") {
        tokens.nextToken(); // Consume the `&`
        list.push(parseNot(tokens, parseValue));
    }
    return { and: list };
}

/** Parse a {@link Expr.Not} using a `parseValue` to parse the potentially negated value */
function parseNot<T>(tokens: Cursor, parseValue: (cursor: Cursor) => Expr.Value<T>): Expr.Not<T> {
    let not = false;
    if (tokens.peekToken()?.type === "logicalNot") {
        tokens.nextToken(); // Consume the `!`
        not = true;
    }
    return { not, value: parseValue(tokens) };
}

/** Parse a single string */
export function parseString(tokens: Cursor): Expr.Value<string> {
    return tokens.nextValue();
}

/** Parse a single {@link Date} */
export function parseDate(tokens: Cursor): Expr.Value<Date> {
    const value = tokens.nextValue();
    const timestamp = Date.parse(value);
    if (Number.isNaN(timestamp)) throw new ParserError({ type: "parseValue", msg: `${value} is not a date` });
    else return new Date(timestamp);
}

/** Parse a single port i.e. a number in the range `1..65535` */
export function parsePort(tokens: Cursor): Expr.Value<number> {
    const value = tokens.nextValue();
    const number = Number(value);
    if (Number.isNaN(number) || number <= 0 || number > 65535)
        throw new ParserError({ type: "parseValue", msg: `${value} is not a valid port` });
    else return number;
}

/** Parse a boolean (true/yes or false/no) */
export function parseBoolean(tokens: Cursor): Expr.Value<boolean> {
    const value = tokens.nextValue();
    switch (value.toLowerCase()) {
        case "true":
        case "yes":
            return true;
        case "false":
        case "no":
            return false;
        default:
            throw new ParserError({ type: "parseValue", msg: `Unknown port protocol: ${value}` });
    }
}

/** Parse a single {@link PortProtocol} */
export function parsePortProtocol(tokens: Cursor): Expr.Value<PortProtocol> {
    const value = tokens.nextValue();
    switch (value.toLowerCase()) {
        case "tcp":
            return PortProtocol.Tcp;
        case "udp":
            return PortProtocol.Udp;
        case "sctp":
            return PortProtocol.Sctp;
        case "unknown":
            return PortProtocol.Unknown;
        default:
            throw new ParserError({ type: "parseValue", msg: `Unknown port protocol: ${value}` });
    }
}

/** Parse a single service transport */
export function parseServiceTransport(tokens: Cursor): Expr.Value<"Raw" | "TLS"> {
    const value = tokens.nextValue();
    switch (value.toLowerCase()) {
        case "raw":
            return "Raw";
        case "tls":
            return "TLS";
        default:
            throw new ParserError({ type: "parseValue", msg: `Unknown service transport: ${value}` });
    }
}

/** Parse a single {@link OsType} */
export function parseOsType(tokens: Cursor): Expr.Value<OsType> {
    const value = tokens.nextValue();
    switch (value.toLowerCase()) {
        case "unknown":
            return OsType.Unknown;
        case "linux":
            return OsType.Linux;
        case "windows":
            return OsType.Windows;
        case "apple":
            return OsType.Apple;
        case "android":
            return OsType.Android;
        case "freebsd":
            return OsType.FreeBsd;
        default:
            throw new ParserError({ type: "parseValue", msg: `Unknown OS type: ${value}` });
    }
}

/** Wraps a `(cursor: Cursor) => Expr.Value<T>` to produce a `(cursor: Cursor) => Expr.Value<Expr.Range<T>>` */
export function wrapRange<T>(parseValue: (cursor: Cursor) => Expr.Value<T>) {
    return function (cursor: Cursor): Expr.Value<Expr.Range<T>> {
        const start = cursor.peekToken()?.type === "rangeOperator" ? null : parseValue(cursor);

        const range = cursor.nextToken();
        if (range === null) {
            throw new ParserError({ type: "unexpectedEnd" });
        } else if (range.type !== "rangeOperator") {
            throw new ParserError({ type: "unexpectedToken", exp: "rangeOperator", got: range });
        }

        let end;
        try {
            const cursor2 = cursor.clone();
            end = parseValue(cursor2);
            cursor.set(cursor2);
        } catch (e) {
            if (e instanceof ParserError) end = null;
            else throw e;
        }

        return {
            start,
            end,
        };
    };
}

/** Wraps a `(cursor: Cursor) => Expr.Value<T>` to produce a `(cursor: Cursor) => Expr.Value<Expr.MaybeRange<T>>` */
export function wrapMaybeRange<T>(parseValue: (cursor: Cursor) => Expr.Value<T>) {
    const parseRange = wrapRange(parseValue);
    return function (cursor: Cursor): Expr.Value<Expr.MaybeRange<T>> {
        const cursor2 = cursor.clone();
        try {
            const range = parseRange(cursor2);
            cursor.set(cursor2);
            return range;
        } catch (e) {
            if (e instanceof ParserError) return parseValue(cursor);
            else throw e;
        }
    };
}

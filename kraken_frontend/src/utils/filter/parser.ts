import { Cursor } from "./cursor";
import { DomainAST, Expr, GlobalAST, HostAST, PortAST, ServiceAST } from "./ast";
import { Token, tokenize } from "./lexer";
import ParserError from "./error";
import { Err, Result } from "../result";
import { PortProtocol } from "../../api/generated";

/**
 * Parse a string into a {@link GlobalAST}
 *
 * @throws ParserError
 */
export function parseGlobalAST(input: string): GlobalAST {
    const ast: GlobalAST = { tags: [], createdAt: [] };
    parseAst(input, (column, cursor) => {
        switch (column) {
            case "tags":
                ast.tags.push(parseOr(cursor, parseString));
                break;
            case "created_at":
                ast.createdAt.push(parseOr(cursor, wrapRange(parseDate)));
                break;
            default:
                throw new ParserError({ type: "unknownColumn", column });
        }
    });
    return ast;
}

/**
 * Parse a string into a {@link DomainAST}
 *
 * @throws ParserError
 */
export function parseDomainAST(input: string): DomainAST {
    const ast: DomainAST = { tags: [], createdAt: [], domains: [] };
    parseAst(input, (column, cursor) => {
        switch (column) {
            case "tags":
                ast.tags.push(parseOr(cursor, parseString));
                break;
            case "created_at":
                ast.createdAt.push(parseOr(cursor, wrapRange(parseDate)));
                break;
            case "domains":
                ast.domains.push(parseOr(cursor, parseString));
                break;
            default:
                throw new ParserError({ type: "unknownColumn", column });
        }
    });
    return ast;
}

/**
 * Parse a string into a {@link HostAST}
 *
 * @throws ParserError
 */
export function parseHostAST(input: string): HostAST {
    const ast: HostAST = { tags: [], createdAt: [], ips: [] };
    parseAst(input, (column, cursor) => {
        switch (column) {
            case "tags":
                ast.tags.push(parseOr(cursor, parseString));
                break;
            case "created_at":
                ast.createdAt.push(parseOr(cursor, wrapRange(parseDate)));
                break;
            case "ips":
                ast.ips.push(parseOr(cursor, parseString));
                break;
            default:
                throw new ParserError({ type: "unknownColumn", column });
        }
    });
    return ast;
}

/**
 * Parse a string into a {@link PortAST}
 *
 * @throws ParserError
 */
export function parsePortAST(input: string): PortAST {
    const ast: PortAST = { tags: [], createdAt: [], ports: [], ips: [], protocols: [] };
    parseAst(input, (column, cursor) => {
        switch (column) {
            case "tags":
                ast.tags.push(parseOr(cursor, parseString));
                break;
            case "created_at":
                ast.createdAt.push(parseOr(cursor, wrapRange(parseDate)));
                break;
            case "ports":
                ast.ports.push(parseOr(cursor, wrapMaybeRange(parsePort)));
                break;
            case "ips":
                ast.ips.push(parseOr(cursor, parseString));
                break;
            case "protocols":
                ast.protocols.push(parseOr(cursor, parsePortProtocol));
                break;
            default:
                throw new ParserError({ type: "unknownColumn", column });
        }
    });
    return ast;
}

/**
 * Parse a string into a {@link ServiceAST}
 *
 * @throws ParserError
 */
export function parseServiceAST(input: string): ServiceAST {
    const ast: ServiceAST = { tags: [], createdAt: [], ports: [], ips: [], names: [] };
    parseAst(input, (column, cursor) => {
        switch (column) {
            case "tags":
                ast.tags.push(parseOr(cursor, parseString));
                break;
            case "created_at":
                ast.createdAt.push(parseOr(cursor, wrapRange(parseDate)));
                break;
            case "ports":
                ast.ports.push(parseOr(cursor, wrapMaybeRange(parsePort)));
                break;
            case "ips":
                ast.ips.push(parseOr(cursor, parseString));
                break;
            case "names":
                ast.names.push(parseOr(cursor, parseString));
                break;
            default:
                throw new ParserError({ type: "unknownColumn", column });
        }
    });
    return ast;
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
    while (true) {
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
function parseString(tokens: Cursor): Expr.Value<string> {
    return tokens.nextValue();
}

/** Parse a single {@link Date} */
function parseDate(tokens: Cursor): Expr.Value<Date> {
    const value = tokens.nextValue();
    const timestamp = Date.parse(value);
    if (Number.isNaN(timestamp)) throw new ParserError({ type: "parseValue", msg: `${value} is not a date` });
    else return new Date(timestamp);
}

/** Parse a single port i.e. a number in the range `1..65535` */
function parsePort(tokens: Cursor): Expr.Value<number> {
    const value = tokens.nextValue();
    const number = Number(value);
    if (Number.isNaN(number) || number <= 0 || number > 65535)
        throw new ParserError({ type: "parseValue", msg: `${value} is not a valid port` });
    else return number;
}

/** Parse a single {@link PortProtocol} */
function parsePortProtocol(tokens: Cursor): Expr.Value<PortProtocol> {
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

/** Wraps a `(cursor: Cursor) => Expr.Value<T>` to produce a `(cursor: Cursor) => Expr.Value<Expr.Range<T>>` */
function wrapRange<T>(parseValue: (cursor: Cursor) => Expr.Value<T>) {
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
function wrapMaybeRange<T>(parseValue: (cursor: Cursor) => Expr.Value<T>) {
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
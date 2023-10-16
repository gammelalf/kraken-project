/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.1.0
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


/**
 * This type holds all possible error types that can be returned by the API.
 * 
 * Numbers between 1000 and 1999 (inclusive) are client errors that can be handled by the client.
 * Numbers between 2000 and 2999 (inclusive) are server errors.
 * @export
 */
export const ApiStatusCode = {
    NUMBER_1000: 1000,
    NUMBER_1001: 1001,
    NUMBER_1002: 1002,
    NUMBER_1003: 1003,
    NUMBER_1004: 1004,
    NUMBER_1005: 1005,
    NUMBER_1006: 1006,
    NUMBER_1007: 1007,
    NUMBER_1008: 1008,
    NUMBER_1009: 1009,
    NUMBER_1010: 1010,
    NUMBER_1011: 1011,
    NUMBER_1012: 1012,
    NUMBER_1013: 1013,
    NUMBER_1014: 1014,
    NUMBER_1015: 1015,
    NUMBER_1016: 1016,
    NUMBER_1017: 1017,
    NUMBER_1018: 1018,
    NUMBER_1019: 1019,
    NUMBER_1020: 1020,
    NUMBER_1021: 1021,
    NUMBER_1022: 1022,
    NUMBER_1023: 1023,
    NUMBER_1024: 1024,
    NUMBER_2000: 2000,
    NUMBER_2001: 2001,
    NUMBER_2002: 2002,
    NUMBER_2003: 2003,
    NUMBER_2004: 2004,
    NUMBER_2005: 2005
} as const;
export type ApiStatusCode = typeof ApiStatusCode[keyof typeof ApiStatusCode];


export function ApiStatusCodeFromJSON(json: any): ApiStatusCode {
    return ApiStatusCodeFromJSONTyped(json, false);
}

export function ApiStatusCodeFromJSONTyped(json: any, ignoreDiscriminator: boolean): ApiStatusCode {
    return json as ApiStatusCode;
}

export function ApiStatusCodeToJSON(value?: ApiStatusCode | null): any {
    return value as any;
}


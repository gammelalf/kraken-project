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

import { exists, mapValues } from '../runtime';
/**
 * A notification about a search result
 * @export
 * @interface WsMessageOneOf5
 */
export interface WsMessageOneOf5 {
    /**
     * The corresponding id of the search results
     * @type {string}
     * @memberof WsMessageOneOf5
     */
    searchUuid: string;
    /**
     * A result entry
     * @type {string}
     * @memberof WsMessageOneOf5
     */
    resultUuid: string;
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf5
     */
    type: WsMessageOneOf5TypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOf5TypeEnum = {
    SearchNotify: 'SearchNotify'
} as const;
export type WsMessageOneOf5TypeEnum = typeof WsMessageOneOf5TypeEnum[keyof typeof WsMessageOneOf5TypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf5 interface.
 */
export function instanceOfWsMessageOneOf5(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "searchUuid" in value;
    isInstance = isInstance && "resultUuid" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOf5FromJSON(json: any): WsMessageOneOf5 {
    return WsMessageOneOf5FromJSONTyped(json, false);
}

export function WsMessageOneOf5FromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf5 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'searchUuid': json['search_uuid'],
        'resultUuid': json['result_uuid'],
        'type': json['type'],
    };
}

export function WsMessageOneOf5ToJSON(value?: WsMessageOneOf5 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'search_uuid': value.searchUuid,
        'result_uuid': value.resultUuid,
        'type': value.type,
    };
}


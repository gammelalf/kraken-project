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
 * A notification about a finished search
 * @export
 * @interface WsMessageOneOf4
 */
export interface WsMessageOneOf4 {
    /**
     * The corresponding id of the search
     * @type {string}
     * @memberof WsMessageOneOf4
     */
    searchUuid: string;
    /**
     * Whether the search was finished successfully
     * @type {boolean}
     * @memberof WsMessageOneOf4
     */
    finishedSuccessful: boolean;
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf4
     */
    type: WsMessageOneOf4TypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOf4TypeEnum = {
    SearchFinished: 'SearchFinished'
} as const;
export type WsMessageOneOf4TypeEnum = typeof WsMessageOneOf4TypeEnum[keyof typeof WsMessageOneOf4TypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf4 interface.
 */
export function instanceOfWsMessageOneOf4(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "searchUuid" in value;
    isInstance = isInstance && "finishedSuccessful" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOf4FromJSON(json: any): WsMessageOneOf4 {
    return WsMessageOneOf4FromJSONTyped(json, false);
}

export function WsMessageOneOf4FromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf4 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'searchUuid': json['search_uuid'],
        'finishedSuccessful': json['finished_successful'],
        'type': json['type'],
    };
}

export function WsMessageOneOf4ToJSON(value?: WsMessageOneOf4 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'search_uuid': value.searchUuid,
        'finished_successful': value.finishedSuccessful,
        'type': value.type,
    };
}


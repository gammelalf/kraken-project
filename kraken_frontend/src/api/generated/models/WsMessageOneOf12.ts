/* tslint:disable */
/* eslint-disable */
/**
 * kraken
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.5.0
 * Contact: git@omikron.dev
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

import { exists, mapValues } from '../runtime';
/**
 * A result for a DNS resolution requests
 * @export
 * @interface WsMessageOneOf12
 */
export interface WsMessageOneOf12 {
    /**
     * The corresponding id of the attack
     * @type {string}
     * @memberof WsMessageOneOf12
     */
    attackUuid: string;
    /**
     * The source address that was queried
     * @type {string}
     * @memberof WsMessageOneOf12
     */
    source: string;
    /**
     * The destination address that was returned
     * @type {string}
     * @memberof WsMessageOneOf12
     */
    destination: string;
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf12
     */
    type: WsMessageOneOf12TypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOf12TypeEnum = {
    DnsResolutionResult: 'DnsResolutionResult'
} as const;
export type WsMessageOneOf12TypeEnum = typeof WsMessageOneOf12TypeEnum[keyof typeof WsMessageOneOf12TypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf12 interface.
 */
export function instanceOfWsMessageOneOf12(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "attackUuid" in value;
    isInstance = isInstance && "source" in value;
    isInstance = isInstance && "destination" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOf12FromJSON(json: any): WsMessageOneOf12 {
    return WsMessageOneOf12FromJSONTyped(json, false);
}

export function WsMessageOneOf12FromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf12 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'attackUuid': json['attack_uuid'],
        'source': json['source'],
        'destination': json['destination'],
        'type': json['type'],
    };
}

export function WsMessageOneOf12ToJSON(value?: WsMessageOneOf12 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'attack_uuid': value.attackUuid,
        'source': value.source,
        'destination': value.destination,
        'type': value.type,
    };
}


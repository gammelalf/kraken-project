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
 * A result to service detection request
 * @export
 * @interface WsMessageOneOf10
 */
export interface WsMessageOneOf10 {
    /**
     * The corresponding id of the attack
     * @type {string}
     * @memberof WsMessageOneOf10
     */
    attackUuid: string;
    /**
     * Name of the service
     * @type {string}
     * @memberof WsMessageOneOf10
     */
    service: string;
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf10
     */
    type: WsMessageOneOf10TypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOf10TypeEnum = {
    ServiceDetectionResult: 'ServiceDetectionResult'
} as const;
export type WsMessageOneOf10TypeEnum = typeof WsMessageOneOf10TypeEnum[keyof typeof WsMessageOneOf10TypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf10 interface.
 */
export function instanceOfWsMessageOneOf10(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "attackUuid" in value;
    isInstance = isInstance && "service" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOf10FromJSON(json: any): WsMessageOneOf10 {
    return WsMessageOneOf10FromJSONTyped(json, false);
}

export function WsMessageOneOf10FromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf10 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'attackUuid': json['attack_uuid'],
        'service': json['service'],
        'type': json['type'],
    };
}

export function WsMessageOneOf10ToJSON(value?: WsMessageOneOf10 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'attack_uuid': value.attackUuid,
        'service': value.service,
        'type': value.type,
    };
}


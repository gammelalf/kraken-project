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
 * A finding definition was deleted
 * @export
 * @interface WsMessageOneOf28
 */
export interface WsMessageOneOf28 {
    /**
     * The uuid of the finding definition
     * @type {string}
     * @memberof WsMessageOneOf28
     */
    uuid: string;
    /**
     * 
     * @type {string}
     * @memberof WsMessageOneOf28
     */
    type: WsMessageOneOf28TypeEnum;
}


/**
 * @export
 */
export const WsMessageOneOf28TypeEnum = {
    DeletedFindingDefinition: 'DeletedFindingDefinition'
} as const;
export type WsMessageOneOf28TypeEnum = typeof WsMessageOneOf28TypeEnum[keyof typeof WsMessageOneOf28TypeEnum];


/**
 * Check if a given object implements the WsMessageOneOf28 interface.
 */
export function instanceOfWsMessageOneOf28(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "type" in value;

    return isInstance;
}

export function WsMessageOneOf28FromJSON(json: any): WsMessageOneOf28 {
    return WsMessageOneOf28FromJSONTyped(json, false);
}

export function WsMessageOneOf28FromJSONTyped(json: any, ignoreDiscriminator: boolean): WsMessageOneOf28 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'type': json['type'],
    };
}

export function WsMessageOneOf28ToJSON(value?: WsMessageOneOf28 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'type': value.type,
    };
}


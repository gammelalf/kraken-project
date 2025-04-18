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
 * A simple representation of a host alive result
 * @export
 * @interface SimpleHostAliveResult
 */
export interface SimpleHostAliveResult {
    /**
     * The primary key
     * @type {string}
     * @memberof SimpleHostAliveResult
     */
    uuid: string;
    /**
     * The attack which produced this result
     * @type {string}
     * @memberof SimpleHostAliveResult
     */
    attack: string;
    /**
     * The point in time, this result was produced
     * @type {Date}
     * @memberof SimpleHostAliveResult
     */
    createdAt: Date;
    /**
     * A host that responded
     * @type {string}
     * @memberof SimpleHostAliveResult
     */
    host: string;
}

/**
 * Check if a given object implements the SimpleHostAliveResult interface.
 */
export function instanceOfSimpleHostAliveResult(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "attack" in value;
    isInstance = isInstance && "createdAt" in value;
    isInstance = isInstance && "host" in value;

    return isInstance;
}

export function SimpleHostAliveResultFromJSON(json: any): SimpleHostAliveResult {
    return SimpleHostAliveResultFromJSONTyped(json, false);
}

export function SimpleHostAliveResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): SimpleHostAliveResult {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'attack': json['attack'],
        'createdAt': (new Date(json['created_at'])),
        'host': json['host'],
    };
}

export function SimpleHostAliveResultToJSON(value?: SimpleHostAliveResult | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'attack': value.attack,
        'created_at': (value.createdAt.toISOString()),
        'host': value.host,
    };
}


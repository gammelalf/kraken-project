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
import type { SimpleHost } from './SimpleHost';
import {
    SimpleHostFromJSON,
    SimpleHostFromJSONTyped,
    SimpleHostToJSON,
} from './SimpleHost';

/**
 * 
 * @export
 * @interface FindingAffectedObjectOneOf1
 */
export interface FindingAffectedObjectOneOf1 {
    /**
     * 
     * @type {SimpleHost}
     * @memberof FindingAffectedObjectOneOf1
     */
    host: SimpleHost;
}

/**
 * Check if a given object implements the FindingAffectedObjectOneOf1 interface.
 */
export function instanceOfFindingAffectedObjectOneOf1(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "host" in value;

    return isInstance;
}

export function FindingAffectedObjectOneOf1FromJSON(json: any): FindingAffectedObjectOneOf1 {
    return FindingAffectedObjectOneOf1FromJSONTyped(json, false);
}

export function FindingAffectedObjectOneOf1FromJSONTyped(json: any, ignoreDiscriminator: boolean): FindingAffectedObjectOneOf1 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'host': SimpleHostFromJSON(json['Host']),
    };
}

export function FindingAffectedObjectOneOf1ToJSON(value?: FindingAffectedObjectOneOf1 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Host': SimpleHostToJSON(value.host),
    };
}


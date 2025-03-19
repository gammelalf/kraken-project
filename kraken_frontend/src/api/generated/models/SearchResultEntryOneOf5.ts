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
import type { SimpleDnsTxtScanResult } from './SimpleDnsTxtScanResult';
import {
    SimpleDnsTxtScanResultFromJSON,
    SimpleDnsTxtScanResultFromJSONTyped,
    SimpleDnsTxtScanResultToJSON,
} from './SimpleDnsTxtScanResult';

/**
 * 
 * @export
 * @interface SearchResultEntryOneOf5
 */
export interface SearchResultEntryOneOf5 {
    /**
     * 
     * @type {SimpleDnsTxtScanResult}
     * @memberof SearchResultEntryOneOf5
     */
    dnsTxtScanResultEntry: SimpleDnsTxtScanResult;
}

/**
 * Check if a given object implements the SearchResultEntryOneOf5 interface.
 */
export function instanceOfSearchResultEntryOneOf5(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "dnsTxtScanResultEntry" in value;

    return isInstance;
}

export function SearchResultEntryOneOf5FromJSON(json: any): SearchResultEntryOneOf5 {
    return SearchResultEntryOneOf5FromJSONTyped(json, false);
}

export function SearchResultEntryOneOf5FromJSONTyped(json: any, ignoreDiscriminator: boolean): SearchResultEntryOneOf5 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'dnsTxtScanResultEntry': SimpleDnsTxtScanResultFromJSON(json['DnsTxtScanResultEntry']),
    };
}

export function SearchResultEntryOneOf5ToJSON(value?: SearchResultEntryOneOf5 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'DnsTxtScanResultEntry': SimpleDnsTxtScanResultToJSON(value.dnsTxtScanResultEntry),
    };
}


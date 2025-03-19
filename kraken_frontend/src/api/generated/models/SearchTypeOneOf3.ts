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
import type { SearchType } from './SearchType';
import {
    SearchTypeFromJSON,
    SearchTypeFromJSONTyped,
    SearchTypeToJSON,
} from './SearchType';

/**
 * 
 * @export
 * @interface SearchTypeOneOf3
 */
export interface SearchTypeOneOf3 {
    /**
     * Add multiple [SearchType]s with an OR
     * @type {Array<SearchType>}
     * @memberof SearchTypeOneOf3
     */
    or: Array<SearchType>;
}

/**
 * Check if a given object implements the SearchTypeOneOf3 interface.
 */
export function instanceOfSearchTypeOneOf3(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "or" in value;

    return isInstance;
}

export function SearchTypeOneOf3FromJSON(json: any): SearchTypeOneOf3 {
    return SearchTypeOneOf3FromJSONTyped(json, false);
}

export function SearchTypeOneOf3FromJSONTyped(json: any, ignoreDiscriminator: boolean): SearchTypeOneOf3 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'or': ((json['Or'] as Array<any>).map(SearchTypeFromJSON)),
    };
}

export function SearchTypeOneOf3ToJSON(value?: SearchTypeOneOf3 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Or': ((value.or as Array<any>).map(SearchTypeToJSON)),
    };
}


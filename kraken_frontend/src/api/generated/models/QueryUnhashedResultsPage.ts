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
import type { SimpleQueryUnhashedResult } from './SimpleQueryUnhashedResult';
import {
    SimpleQueryUnhashedResultFromJSON,
    SimpleQueryUnhashedResultFromJSONTyped,
    SimpleQueryUnhashedResultToJSON,
} from './SimpleQueryUnhashedResult';

/**
 * Response containing paginated data
 * @export
 * @interface QueryUnhashedResultsPage
 */
export interface QueryUnhashedResultsPage {
    /**
     * The page's items
     * @type {Array<SimpleQueryUnhashedResult>}
     * @memberof QueryUnhashedResultsPage
     */
    items: Array<SimpleQueryUnhashedResult>;
    /**
     * The limit this page was retrieved with
     * @type {number}
     * @memberof QueryUnhashedResultsPage
     */
    limit: number;
    /**
     * The offset this page was retrieved with
     * @type {number}
     * @memberof QueryUnhashedResultsPage
     */
    offset: number;
    /**
     * The total number of items this page is a subset of
     * @type {number}
     * @memberof QueryUnhashedResultsPage
     */
    total: number;
}

/**
 * Check if a given object implements the QueryUnhashedResultsPage interface.
 */
export function instanceOfQueryUnhashedResultsPage(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "items" in value;
    isInstance = isInstance && "limit" in value;
    isInstance = isInstance && "offset" in value;
    isInstance = isInstance && "total" in value;

    return isInstance;
}

export function QueryUnhashedResultsPageFromJSON(json: any): QueryUnhashedResultsPage {
    return QueryUnhashedResultsPageFromJSONTyped(json, false);
}

export function QueryUnhashedResultsPageFromJSONTyped(json: any, ignoreDiscriminator: boolean): QueryUnhashedResultsPage {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'items': ((json['items'] as Array<any>).map(SimpleQueryUnhashedResultFromJSON)),
        'limit': json['limit'],
        'offset': json['offset'],
        'total': json['total'],
    };
}

export function QueryUnhashedResultsPageToJSON(value?: QueryUnhashedResultsPage | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'items': ((value.items as Array<any>).map(SimpleQueryUnhashedResultToJSON)),
        'limit': value.limit,
        'offset': value.offset,
        'total': value.total,
    };
}


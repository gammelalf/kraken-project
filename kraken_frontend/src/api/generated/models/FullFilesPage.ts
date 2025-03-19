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
import type { FullFile } from './FullFile';
import {
    FullFileFromJSON,
    FullFileFromJSONTyped,
    FullFileToJSON,
} from './FullFile';

/**
 * Response containing paginated data
 * @export
 * @interface FullFilesPage
 */
export interface FullFilesPage {
    /**
     * The page's items
     * @type {Array<FullFile>}
     * @memberof FullFilesPage
     */
    items: Array<FullFile>;
    /**
     * The limit this page was retrieved with
     * @type {number}
     * @memberof FullFilesPage
     */
    limit: number;
    /**
     * The offset this page was retrieved with
     * @type {number}
     * @memberof FullFilesPage
     */
    offset: number;
    /**
     * The total number of items this page is a subset of
     * @type {number}
     * @memberof FullFilesPage
     */
    total: number;
}

/**
 * Check if a given object implements the FullFilesPage interface.
 */
export function instanceOfFullFilesPage(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "items" in value;
    isInstance = isInstance && "limit" in value;
    isInstance = isInstance && "offset" in value;
    isInstance = isInstance && "total" in value;

    return isInstance;
}

export function FullFilesPageFromJSON(json: any): FullFilesPage {
    return FullFilesPageFromJSONTyped(json, false);
}

export function FullFilesPageFromJSONTyped(json: any, ignoreDiscriminator: boolean): FullFilesPage {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'items': ((json['items'] as Array<any>).map(FullFileFromJSON)),
        'limit': json['limit'],
        'offset': json['offset'],
        'total': json['total'],
    };
}

export function FullFilesPageToJSON(value?: FullFilesPage | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'items': ((value.items as Array<any>).map(FullFileToJSON)),
        'limit': value.limit,
        'offset': value.offset,
        'total': value.total,
    };
}


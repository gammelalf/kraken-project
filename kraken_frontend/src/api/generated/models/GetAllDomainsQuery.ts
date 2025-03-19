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
 * Query parameters for filtering the domains to get
 * @export
 * @interface GetAllDomainsQuery
 */
export interface GetAllDomainsQuery {
    /**
     * Number of items to retrieve
     * @type {number}
     * @memberof GetAllDomainsQuery
     */
    limit: number;
    /**
     * Position in the whole list to start retrieving from
     * @type {number}
     * @memberof GetAllDomainsQuery
     */
    offset: number;
    /**
     * Only get domains pointing to a specific host
     * 
     * This includes domains which point to another domain which points to this host.
     * @type {string}
     * @memberof GetAllDomainsQuery
     */
    host?: string | null;
    /**
     * An optional general filter to apply
     * @type {string}
     * @memberof GetAllDomainsQuery
     */
    globalFilter?: string | null;
    /**
     * An optional domain specific filter to apply
     * @type {string}
     * @memberof GetAllDomainsQuery
     */
    domainFilter?: string | null;
}

/**
 * Check if a given object implements the GetAllDomainsQuery interface.
 */
export function instanceOfGetAllDomainsQuery(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "limit" in value;
    isInstance = isInstance && "offset" in value;

    return isInstance;
}

export function GetAllDomainsQueryFromJSON(json: any): GetAllDomainsQuery {
    return GetAllDomainsQueryFromJSONTyped(json, false);
}

export function GetAllDomainsQueryFromJSONTyped(json: any, ignoreDiscriminator: boolean): GetAllDomainsQuery {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'limit': json['limit'],
        'offset': json['offset'],
        'host': !exists(json, 'host') ? undefined : json['host'],
        'globalFilter': !exists(json, 'global_filter') ? undefined : json['global_filter'],
        'domainFilter': !exists(json, 'domain_filter') ? undefined : json['domain_filter'],
    };
}

export function GetAllDomainsQueryToJSON(value?: GetAllDomainsQuery | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'limit': value.limit,
        'offset': value.offset,
        'host': value.host,
        'global_filter': value.globalFilter,
        'domain_filter': value.domainFilter,
    };
}


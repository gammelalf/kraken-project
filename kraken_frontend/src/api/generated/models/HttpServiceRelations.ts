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
import type { SimpleDomain } from './SimpleDomain';
import {
    SimpleDomainFromJSON,
    SimpleDomainFromJSONTyped,
    SimpleDomainToJSON,
} from './SimpleDomain';
import type { SimpleHost } from './SimpleHost';
import {
    SimpleHostFromJSON,
    SimpleHostFromJSONTyped,
    SimpleHostToJSON,
} from './SimpleHost';
import type { SimplePort } from './SimplePort';
import {
    SimplePortFromJSON,
    SimplePortFromJSONTyped,
    SimplePortToJSON,
} from './SimplePort';

/**
 * A http service's direct relations
 * @export
 * @interface HttpServiceRelations
 */
export interface HttpServiceRelations {
    /**
     * 
     * @type {SimpleHost}
     * @memberof HttpServiceRelations
     */
    host: SimpleHost;
    /**
     * 
     * @type {SimplePort}
     * @memberof HttpServiceRelations
     */
    port: SimplePort;
    /**
     * 
     * @type {SimpleDomain}
     * @memberof HttpServiceRelations
     */
    domain?: SimpleDomain | null;
}

/**
 * Check if a given object implements the HttpServiceRelations interface.
 */
export function instanceOfHttpServiceRelations(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "host" in value;
    isInstance = isInstance && "port" in value;

    return isInstance;
}

export function HttpServiceRelationsFromJSON(json: any): HttpServiceRelations {
    return HttpServiceRelationsFromJSONTyped(json, false);
}

export function HttpServiceRelationsFromJSONTyped(json: any, ignoreDiscriminator: boolean): HttpServiceRelations {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'host': SimpleHostFromJSON(json['host']),
        'port': SimplePortFromJSON(json['port']),
        'domain': !exists(json, 'domain') ? undefined : SimpleDomainFromJSON(json['domain']),
    };
}

export function HttpServiceRelationsToJSON(value?: HttpServiceRelations | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'host': SimpleHostToJSON(value.host),
        'port': SimplePortToJSON(value.port),
        'domain': SimpleDomainToJSON(value.domain),
    };
}


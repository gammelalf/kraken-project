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
import type { SimpleHttpService } from './SimpleHttpService';
import {
    SimpleHttpServiceFromJSON,
    SimpleHttpServiceFromJSONTyped,
    SimpleHttpServiceToJSON,
} from './SimpleHttpService';
import type { SimplePort } from './SimplePort';
import {
    SimplePortFromJSON,
    SimplePortFromJSONTyped,
    SimplePortToJSON,
} from './SimplePort';
import type { SimpleService } from './SimpleService';
import {
    SimpleServiceFromJSON,
    SimpleServiceFromJSONTyped,
    SimpleServiceToJSON,
} from './SimpleService';

/**
 * A host's direct relations
 * @export
 * @interface HostRelations
 */
export interface HostRelations {
    /**
     * This host's ports
     * @type {Array<SimplePort>}
     * @memberof HostRelations
     */
    ports: Array<SimplePort>;
    /**
     * This host's services
     * @type {Array<SimpleService>}
     * @memberof HostRelations
     */
    services: Array<SimpleService>;
    /**
     * Domains pointing to this host via a direct `A` or `AAAA` record
     * @type {Array<SimpleDomain>}
     * @memberof HostRelations
     */
    directDomains: Array<SimpleDomain>;
    /**
     * Domains pointing to this host via a `CNAME` record which eventually resolves to the host
     * @type {Array<SimpleDomain>}
     * @memberof HostRelations
     */
    indirectDomains: Array<SimpleDomain>;
    /**
     * This host's http services
     * @type {Array<SimpleHttpService>}
     * @memberof HostRelations
     */
    httpServices: Array<SimpleHttpService>;
}

/**
 * Check if a given object implements the HostRelations interface.
 */
export function instanceOfHostRelations(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "ports" in value;
    isInstance = isInstance && "services" in value;
    isInstance = isInstance && "directDomains" in value;
    isInstance = isInstance && "indirectDomains" in value;
    isInstance = isInstance && "httpServices" in value;

    return isInstance;
}

export function HostRelationsFromJSON(json: any): HostRelations {
    return HostRelationsFromJSONTyped(json, false);
}

export function HostRelationsFromJSONTyped(json: any, ignoreDiscriminator: boolean): HostRelations {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'ports': ((json['ports'] as Array<any>).map(SimplePortFromJSON)),
        'services': ((json['services'] as Array<any>).map(SimpleServiceFromJSON)),
        'directDomains': ((json['direct_domains'] as Array<any>).map(SimpleDomainFromJSON)),
        'indirectDomains': ((json['indirect_domains'] as Array<any>).map(SimpleDomainFromJSON)),
        'httpServices': ((json['http_services'] as Array<any>).map(SimpleHttpServiceFromJSON)),
    };
}

export function HostRelationsToJSON(value?: HostRelations | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'ports': ((value.ports as Array<any>).map(SimplePortToJSON)),
        'services': ((value.services as Array<any>).map(SimpleServiceToJSON)),
        'direct_domains': ((value.directDomains as Array<any>).map(SimpleDomainToJSON)),
        'indirect_domains': ((value.indirectDomains as Array<any>).map(SimpleDomainToJSON)),
        'http_services': ((value.httpServices as Array<any>).map(SimpleHttpServiceToJSON)),
    };
}


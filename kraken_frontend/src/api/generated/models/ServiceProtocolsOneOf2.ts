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
import type { ServiceProtocolsOneOf2Udp } from './ServiceProtocolsOneOf2Udp';
import {
    ServiceProtocolsOneOf2UdpFromJSON,
    ServiceProtocolsOneOf2UdpFromJSONTyped,
    ServiceProtocolsOneOf2UdpToJSON,
} from './ServiceProtocolsOneOf2Udp';

/**
 * 
 * @export
 * @interface ServiceProtocolsOneOf2
 */
export interface ServiceProtocolsOneOf2 {
    /**
     * 
     * @type {ServiceProtocolsOneOf2Udp}
     * @memberof ServiceProtocolsOneOf2
     */
    udp: ServiceProtocolsOneOf2Udp;
}

/**
 * Check if a given object implements the ServiceProtocolsOneOf2 interface.
 */
export function instanceOfServiceProtocolsOneOf2(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "udp" in value;

    return isInstance;
}

export function ServiceProtocolsOneOf2FromJSON(json: any): ServiceProtocolsOneOf2 {
    return ServiceProtocolsOneOf2FromJSONTyped(json, false);
}

export function ServiceProtocolsOneOf2FromJSONTyped(json: any, ignoreDiscriminator: boolean): ServiceProtocolsOneOf2 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'udp': ServiceProtocolsOneOf2UdpFromJSON(json['Udp']),
    };
}

export function ServiceProtocolsOneOf2ToJSON(value?: ServiceProtocolsOneOf2 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'Udp': ServiceProtocolsOneOf2UdpToJSON(value.udp),
    };
}


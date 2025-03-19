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

import {
    ServiceProtocolsOneOf,
    instanceOfServiceProtocolsOneOf,
    ServiceProtocolsOneOfFromJSON,
    ServiceProtocolsOneOfFromJSONTyped,
    ServiceProtocolsOneOfToJSON,
} from './ServiceProtocolsOneOf';
import {
    ServiceProtocolsOneOf1,
    instanceOfServiceProtocolsOneOf1,
    ServiceProtocolsOneOf1FromJSON,
    ServiceProtocolsOneOf1FromJSONTyped,
    ServiceProtocolsOneOf1ToJSON,
} from './ServiceProtocolsOneOf1';
import {
    ServiceProtocolsOneOf2,
    instanceOfServiceProtocolsOneOf2,
    ServiceProtocolsOneOf2FromJSON,
    ServiceProtocolsOneOf2FromJSONTyped,
    ServiceProtocolsOneOf2ToJSON,
} from './ServiceProtocolsOneOf2';
import {
    ServiceProtocolsOneOf3,
    instanceOfServiceProtocolsOneOf3,
    ServiceProtocolsOneOf3FromJSON,
    ServiceProtocolsOneOf3FromJSONTyped,
    ServiceProtocolsOneOf3ToJSON,
} from './ServiceProtocolsOneOf3';

/**
 * @type ServiceProtocols
 * The parsed representation for a [`Service`]'s `protocols` field
 * @export
 */
export type ServiceProtocols = ServiceProtocolsOneOf | ServiceProtocolsOneOf1 | ServiceProtocolsOneOf2 | ServiceProtocolsOneOf3;

export function ServiceProtocolsFromJSON(json: any): ServiceProtocols {
    return ServiceProtocolsFromJSONTyped(json, false);
}

export function ServiceProtocolsFromJSONTyped(json: any, ignoreDiscriminator: boolean): ServiceProtocols {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return { ...ServiceProtocolsOneOfFromJSONTyped(json, true), ...ServiceProtocolsOneOf1FromJSONTyped(json, true), ...ServiceProtocolsOneOf2FromJSONTyped(json, true), ...ServiceProtocolsOneOf3FromJSONTyped(json, true) };
}

export function ServiceProtocolsToJSON(value?: ServiceProtocols | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }

    if (instanceOfServiceProtocolsOneOf(value)) {
        return ServiceProtocolsOneOfToJSON(value as ServiceProtocolsOneOf);
    }
    if (instanceOfServiceProtocolsOneOf1(value)) {
        return ServiceProtocolsOneOf1ToJSON(value as ServiceProtocolsOneOf1);
    }
    if (instanceOfServiceProtocolsOneOf2(value)) {
        return ServiceProtocolsOneOf2ToJSON(value as ServiceProtocolsOneOf2);
    }
    if (instanceOfServiceProtocolsOneOf3(value)) {
        return ServiceProtocolsOneOf3ToJSON(value as ServiceProtocolsOneOf3);
    }

    return {};
}


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
/**
 * A simple representation of a bruteforce subdomains result
 * @export
 * @interface SimpleBruteforceSubdomainsResult
 */
export interface SimpleBruteforceSubdomainsResult {
    /**
     * The primary key
     * @type {string}
     * @memberof SimpleBruteforceSubdomainsResult
     */
    uuid: string;
    /**
     * The attack which produced this result
     * @type {string}
     * @memberof SimpleBruteforceSubdomainsResult
     */
    attack: string;
    /**
     * The point in time, this result was produced
     * @type {Date}
     * @memberof SimpleBruteforceSubdomainsResult
     */
    createdAt: Date;
    /**
     * The source address
     * @type {string}
     * @memberof SimpleBruteforceSubdomainsResult
     */
    source: string;
    /**
     * The destination address
     * @type {string}
     * @memberof SimpleBruteforceSubdomainsResult
     */
    destination: string;
    /**
     * The type of DNS Record
     * @type {string}
     * @memberof SimpleBruteforceSubdomainsResult
     */
    dnsRecordType: SimpleBruteforceSubdomainsResultDnsRecordTypeEnum;
}


/**
 * @export
 */
export const SimpleBruteforceSubdomainsResultDnsRecordTypeEnum = {
    A: 'A',
    Aaaa: 'Aaaa',
    Caa: 'Caa',
    Cname: 'Cname',
    Mx: 'Mx',
    Tlsa: 'Tlsa',
    Txt: 'Txt'
} as const;
export type SimpleBruteforceSubdomainsResultDnsRecordTypeEnum = typeof SimpleBruteforceSubdomainsResultDnsRecordTypeEnum[keyof typeof SimpleBruteforceSubdomainsResultDnsRecordTypeEnum];


/**
 * Check if a given object implements the SimpleBruteforceSubdomainsResult interface.
 */
export function instanceOfSimpleBruteforceSubdomainsResult(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "uuid" in value;
    isInstance = isInstance && "attack" in value;
    isInstance = isInstance && "createdAt" in value;
    isInstance = isInstance && "source" in value;
    isInstance = isInstance && "destination" in value;
    isInstance = isInstance && "dnsRecordType" in value;

    return isInstance;
}

export function SimpleBruteforceSubdomainsResultFromJSON(json: any): SimpleBruteforceSubdomainsResult {
    return SimpleBruteforceSubdomainsResultFromJSONTyped(json, false);
}

export function SimpleBruteforceSubdomainsResultFromJSONTyped(json: any, ignoreDiscriminator: boolean): SimpleBruteforceSubdomainsResult {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'uuid': json['uuid'],
        'attack': json['attack'],
        'createdAt': (new Date(json['created_at'])),
        'source': json['source'],
        'destination': json['destination'],
        'dnsRecordType': json['dns_record_type'],
    };
}

export function SimpleBruteforceSubdomainsResultToJSON(value?: SimpleBruteforceSubdomainsResult | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'uuid': value.uuid,
        'attack': value.attack,
        'created_at': (value.createdAt.toISOString()),
        'source': value.source,
        'destination': value.destination,
        'dns_record_type': value.dnsRecordType,
    };
}


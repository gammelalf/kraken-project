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
import type { FullTestSSLResult } from './FullTestSSLResult';
import {
    FullTestSSLResultFromJSON,
    FullTestSSLResultFromJSONTyped,
    FullTestSSLResultToJSON,
} from './FullTestSSLResult';

/**
 * 
 * @export
 * @interface SourceAttackResultOneOf9
 */
export interface SourceAttackResultOneOf9 {
    /**
     * 
     * @type {string}
     * @memberof SourceAttackResultOneOf9
     */
    attackType: SourceAttackResultOneOf9AttackTypeEnum;
    /**
     * The [`AttackType::TestSSL`] and its results
     * @type {Array<FullTestSSLResult>}
     * @memberof SourceAttackResultOneOf9
     */
    results: Array<FullTestSSLResult>;
}


/**
 * @export
 */
export const SourceAttackResultOneOf9AttackTypeEnum = {
    TestSsl: 'TestSSL'
} as const;
export type SourceAttackResultOneOf9AttackTypeEnum = typeof SourceAttackResultOneOf9AttackTypeEnum[keyof typeof SourceAttackResultOneOf9AttackTypeEnum];


/**
 * Check if a given object implements the SourceAttackResultOneOf9 interface.
 */
export function instanceOfSourceAttackResultOneOf9(value: object): boolean {
    let isInstance = true;
    isInstance = isInstance && "attackType" in value;
    isInstance = isInstance && "results" in value;

    return isInstance;
}

export function SourceAttackResultOneOf9FromJSON(json: any): SourceAttackResultOneOf9 {
    return SourceAttackResultOneOf9FromJSONTyped(json, false);
}

export function SourceAttackResultOneOf9FromJSONTyped(json: any, ignoreDiscriminator: boolean): SourceAttackResultOneOf9 {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'attackType': json['attack_type'],
        'results': ((json['results'] as Array<any>).map(FullTestSSLResultFromJSON)),
    };
}

export function SourceAttackResultOneOf9ToJSON(value?: SourceAttackResultOneOf9 | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'attack_type': value.attackType,
        'results': ((value.results as Array<any>).map(FullTestSSLResultToJSON)),
    };
}


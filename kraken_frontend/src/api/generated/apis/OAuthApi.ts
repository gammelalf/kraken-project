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

import * as runtime from "../runtime";
import type {
    ApiErrorResponse,
    CreateAppRequest,
    FullOauthClient,
    GetAppsResponse,
    OpenRequestInfo,
    UpdateAppRequest,
    UuidResponse,
} from "../models";
import {
    ApiErrorResponseFromJSON,
    ApiErrorResponseToJSON,
    CreateAppRequestFromJSON,
    CreateAppRequestToJSON,
    FullOauthClientFromJSON,
    FullOauthClientToJSON,
    GetAppsResponseFromJSON,
    GetAppsResponseToJSON,
    OpenRequestInfoFromJSON,
    OpenRequestInfoToJSON,
    UpdateAppRequestFromJSON,
    UpdateAppRequestToJSON,
    UuidResponseFromJSON,
    UuidResponseToJSON,
} from "../models";

export interface AdminCreateAppRequest {
    createAppRequest: CreateAppRequest;
}

export interface AdminDeleteAppRequest {
    uuid: string;
}

export interface AdminGetAppRequest {
    uuid: string;
}

export interface AdminUpdateAppRequest {
    uuid: string;
    updateAppRequest: UpdateAppRequest;
}

export interface InfoRequest {
    uuid: string;
}

/**
 *
 */
export class OAuthApi extends runtime.BaseAPI {
    /**
     * Create a new application
     * Create a new application
     */
    async adminCreateAppRaw(
        requestParameters: AdminCreateAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<runtime.ApiResponse<UuidResponse>> {
        if (requestParameters.createAppRequest === null || requestParameters.createAppRequest === undefined) {
            throw new runtime.RequiredError(
                "createAppRequest",
                "Required parameter requestParameters.createAppRequest was null or undefined when calling adminCreateApp.",
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters["Content-Type"] = "application/json";

        const response = await this.request(
            {
                path: `/api/v1/admin/applications`,
                method: "POST",
                headers: headerParameters,
                query: queryParameters,
                body: CreateAppRequestToJSON(requestParameters.createAppRequest),
            },
            initOverrides,
        );

        return new runtime.JSONApiResponse(response, (jsonValue) => UuidResponseFromJSON(jsonValue));
    }

    /**
     * Create a new application
     * Create a new application
     */
    async adminCreateApp(
        requestParameters: AdminCreateAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<UuidResponse> {
        const response = await this.adminCreateAppRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Delete an application
     * Delete an application
     */
    async adminDeleteAppRaw(
        requestParameters: AdminDeleteAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError(
                "uuid",
                "Required parameter requestParameters.uuid was null or undefined when calling adminDeleteApp.",
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request(
            {
                path: `/api/v1/admin/applications/{uuid}`.replace(
                    `{${"uuid"}}`,
                    encodeURIComponent(String(requestParameters.uuid)),
                ),
                method: "DELETE",
                headers: headerParameters,
                query: queryParameters,
            },
            initOverrides,
        );

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Delete an application
     * Delete an application
     */
    async adminDeleteApp(
        requestParameters: AdminDeleteAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<void> {
        await this.adminDeleteAppRaw(requestParameters, initOverrides);
    }

    /**
     */
    async adminGetAppRaw(
        requestParameters: AdminGetAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<runtime.ApiResponse<FullOauthClient>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError(
                "uuid",
                "Required parameter requestParameters.uuid was null or undefined when calling adminGetApp.",
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request(
            {
                path: `/api/v1/admin/applications/{uuid}`.replace(
                    `{${"uuid"}}`,
                    encodeURIComponent(String(requestParameters.uuid)),
                ),
                method: "GET",
                headers: headerParameters,
                query: queryParameters,
            },
            initOverrides,
        );

        return new runtime.JSONApiResponse(response, (jsonValue) => FullOauthClientFromJSON(jsonValue));
    }

    /**
     */
    async adminGetApp(
        requestParameters: AdminGetAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<FullOauthClient> {
        const response = await this.adminGetAppRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     */
    async adminGetAppsRaw(
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<runtime.ApiResponse<GetAppsResponse>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request(
            {
                path: `/api/v1/admin/applications`,
                method: "GET",
                headers: headerParameters,
                query: queryParameters,
            },
            initOverrides,
        );

        return new runtime.JSONApiResponse(response, (jsonValue) => GetAppsResponseFromJSON(jsonValue));
    }

    /**
     */
    async adminGetApps(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<GetAppsResponse> {
        const response = await this.adminGetAppsRaw(initOverrides);
        return await response.value();
    }

    /**
     * Update an application
     * Update an application
     */
    async adminUpdateAppRaw(
        requestParameters: AdminUpdateAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError(
                "uuid",
                "Required parameter requestParameters.uuid was null or undefined when calling adminUpdateApp.",
            );
        }

        if (requestParameters.updateAppRequest === null || requestParameters.updateAppRequest === undefined) {
            throw new runtime.RequiredError(
                "updateAppRequest",
                "Required parameter requestParameters.updateAppRequest was null or undefined when calling adminUpdateApp.",
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters["Content-Type"] = "application/json";

        const response = await this.request(
            {
                path: `/api/v1/admin/applications/{uuid}`.replace(
                    `{${"uuid"}}`,
                    encodeURIComponent(String(requestParameters.uuid)),
                ),
                method: "PUT",
                headers: headerParameters,
                query: queryParameters,
                body: UpdateAppRequestToJSON(requestParameters.updateAppRequest),
            },
            initOverrides,
        );

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Update an application
     * Update an application
     */
    async adminUpdateApp(
        requestParameters: AdminUpdateAppRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<void> {
        await this.adminUpdateAppRaw(requestParameters, initOverrides);
    }

    /**
     * Queried by the frontend to display information about the oauth request to the user
     * Queried by the frontend to display information about the oauth request to the user
     */
    async infoRaw(
        requestParameters: InfoRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<runtime.ApiResponse<OpenRequestInfo>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError(
                "uuid",
                "Required parameter requestParameters.uuid was null or undefined when calling info.",
            );
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request(
            {
                path: `/api/v1/oauth/info/{uuid}`.replace(
                    `{${"uuid"}}`,
                    encodeURIComponent(String(requestParameters.uuid)),
                ),
                method: "GET",
                headers: headerParameters,
                query: queryParameters,
            },
            initOverrides,
        );

        return new runtime.JSONApiResponse(response, (jsonValue) => OpenRequestInfoFromJSON(jsonValue));
    }

    /**
     * Queried by the frontend to display information about the oauth request to the user
     * Queried by the frontend to display information about the oauth request to the user
     */
    async info(
        requestParameters: InfoRequest,
        initOverrides?: RequestInit | runtime.InitOverrideFunction,
    ): Promise<OpenRequestInfo> {
        const response = await this.infoRaw(requestParameters, initOverrides);
        return await response.value();
    }
}

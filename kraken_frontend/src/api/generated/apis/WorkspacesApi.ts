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


import * as runtime from '../runtime';
import type {
  ApiErrorResponse,
  CreateWorkspaceRequest,
  FullWorkspace,
  GetAllWorkspacesResponse,
  TransferWorkspaceRequest,
  UpdateWorkspaceRequest,
  UuidResponse,
} from '../models';
import {
    ApiErrorResponseFromJSON,
    ApiErrorResponseToJSON,
    CreateWorkspaceRequestFromJSON,
    CreateWorkspaceRequestToJSON,
    FullWorkspaceFromJSON,
    FullWorkspaceToJSON,
    GetAllWorkspacesResponseFromJSON,
    GetAllWorkspacesResponseToJSON,
    TransferWorkspaceRequestFromJSON,
    TransferWorkspaceRequestToJSON,
    UpdateWorkspaceRequestFromJSON,
    UpdateWorkspaceRequestToJSON,
    UuidResponseFromJSON,
    UuidResponseToJSON,
} from '../models';

export interface CreateWorkspaceOperationRequest {
    createWorkspaceRequest: CreateWorkspaceRequest;
}

export interface DeleteWorkspaceRequest {
    uuid: string;
}

export interface GetWorkspaceRequest {
    uuid: string;
}

export interface TransferOwnershipRequest {
    uuid: string;
    transferWorkspaceRequest: TransferWorkspaceRequest;
}

export interface UpdateWorkspaceOperationRequest {
    uuid: string;
    updateWorkspaceRequest: UpdateWorkspaceRequest;
}

/**
 * 
 */
export class WorkspacesApi extends runtime.BaseAPI {

    /**
     * Create a new workspace
     * Create a new workspace
     */
    async createWorkspaceRaw(requestParameters: CreateWorkspaceOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<UuidResponse>> {
        if (requestParameters.createWorkspaceRequest === null || requestParameters.createWorkspaceRequest === undefined) {
            throw new runtime.RequiredError('createWorkspaceRequest','Required parameter requestParameters.createWorkspaceRequest was null or undefined when calling createWorkspace.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/v1/workspaces`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: CreateWorkspaceRequestToJSON(requestParameters.createWorkspaceRequest),
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => UuidResponseFromJSON(jsonValue));
    }

    /**
     * Create a new workspace
     * Create a new workspace
     */
    async createWorkspace(requestParameters: CreateWorkspaceOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<UuidResponse> {
        const response = await this.createWorkspaceRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Delete a workspace by its id
     * Delete a workspace by its id
     */
    async deleteWorkspaceRaw(requestParameters: DeleteWorkspaceRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError('uuid','Required parameter requestParameters.uuid was null or undefined when calling deleteWorkspace.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/v1/workspaces/{uuid}`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters.uuid))),
            method: 'DELETE',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Delete a workspace by its id
     * Delete a workspace by its id
     */
    async deleteWorkspace(requestParameters: DeleteWorkspaceRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.deleteWorkspaceRaw(requestParameters, initOverrides);
    }

    /**
     * Retrieve all workspaces owned by executing user  For administration access, look at the `/admin/workspaces` endpoint.
     * Retrieve all workspaces owned by executing user
     */
    async getAllWorkspacesRaw(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<GetAllWorkspacesResponse>> {
        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/v1/workspaces`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => GetAllWorkspacesResponseFromJSON(jsonValue));
    }

    /**
     * Retrieve all workspaces owned by executing user  For administration access, look at the `/admin/workspaces` endpoint.
     * Retrieve all workspaces owned by executing user
     */
    async getAllWorkspaces(initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<GetAllWorkspacesResponse> {
        const response = await this.getAllWorkspacesRaw(initOverrides);
        return await response.value();
    }

    /**
     * Retrieve a workspace by id
     * Retrieve a workspace by id
     */
    async getWorkspaceRaw(requestParameters: GetWorkspaceRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<FullWorkspace>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError('uuid','Required parameter requestParameters.uuid was null or undefined when calling getWorkspace.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        const response = await this.request({
            path: `/api/v1/workspaces/{uuid}`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters.uuid))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        }, initOverrides);

        return new runtime.JSONApiResponse(response, (jsonValue) => FullWorkspaceFromJSON(jsonValue));
    }

    /**
     * Retrieve a workspace by id
     * Retrieve a workspace by id
     */
    async getWorkspace(requestParameters: GetWorkspaceRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<FullWorkspace> {
        const response = await this.getWorkspaceRaw(requestParameters, initOverrides);
        return await response.value();
    }

    /**
     * Transfer ownership to another account  You will loose access to the workspace.
     * Transfer ownership to another account
     */
    async transferOwnershipRaw(requestParameters: TransferOwnershipRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError('uuid','Required parameter requestParameters.uuid was null or undefined when calling transferOwnership.');
        }

        if (requestParameters.transferWorkspaceRequest === null || requestParameters.transferWorkspaceRequest === undefined) {
            throw new runtime.RequiredError('transferWorkspaceRequest','Required parameter requestParameters.transferWorkspaceRequest was null or undefined when calling transferOwnership.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/v1/workspaces/{uuid}/transfer`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters.uuid))),
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: TransferWorkspaceRequestToJSON(requestParameters.transferWorkspaceRequest),
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Transfer ownership to another account  You will loose access to the workspace.
     * Transfer ownership to another account
     */
    async transferOwnership(requestParameters: TransferOwnershipRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.transferOwnershipRaw(requestParameters, initOverrides);
    }

    /**
     * Updates a workspace by its id  All parameter are optional, but at least one of them must be specified.  `name` must not be empty.  You can set `description` to null to remove the description from the database. If you leave the parameter out, the description will remain unchanged.
     * Updates a workspace by its id
     */
    async updateWorkspaceRaw(requestParameters: UpdateWorkspaceOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.uuid === null || requestParameters.uuid === undefined) {
            throw new runtime.RequiredError('uuid','Required parameter requestParameters.uuid was null or undefined when calling updateWorkspace.');
        }

        if (requestParameters.updateWorkspaceRequest === null || requestParameters.updateWorkspaceRequest === undefined) {
            throw new runtime.RequiredError('updateWorkspaceRequest','Required parameter requestParameters.updateWorkspaceRequest was null or undefined when calling updateWorkspace.');
        }

        const queryParameters: any = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        const response = await this.request({
            path: `/api/v1/workspaces/{uuid}`.replace(`{${"uuid"}}`, encodeURIComponent(String(requestParameters.uuid))),
            method: 'PUT',
            headers: headerParameters,
            query: queryParameters,
            body: UpdateWorkspaceRequestToJSON(requestParameters.updateWorkspaceRequest),
        }, initOverrides);

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Updates a workspace by its id  All parameter are optional, but at least one of them must be specified.  `name` must not be empty.  You can set `description` to null to remove the description from the database. If you leave the parameter out, the description will remain unchanged.
     * Updates a workspace by its id
     */
    async updateWorkspace(requestParameters: UpdateWorkspaceOperationRequest, initOverrides?: RequestInit | runtime.InitOverrideFunction): Promise<void> {
        await this.updateWorkspaceRaw(requestParameters, initOverrides);
    }

}

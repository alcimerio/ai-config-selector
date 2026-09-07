// Package commonprofile owns target-independent Profile capabilities, their
// defaults, and the authority represented by their admitted selections.
package commonprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

const (
	WorkspaceCapabilityID      = "workspace"
	WorkspaceCapabilityVersion = 1
)

type WorkspaceContribution struct{ access launch.WorkspaceAccess }

func (WorkspaceContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (contribution WorkspaceContribution) PlanResolved(ctx context.Context, workingDirectory string, sourceVersion int, _ string, plan *launch.Plan) error {
	if sourceVersion < profile.CurrentVersion {
		return nil
	}
	return contribution.Plan(ctx, workingDirectory, plan)
}
func (WorkspaceContribution) Materialize(string) error                                 { return nil }
func (WorkspaceContribution) Verify(context.Context, launch.VerificationContext) error { return nil }
func (contribution WorkspaceContribution) SemanticFacts(_ int, _ string) authority.Facts {
	source := authority.FactSource{Kind: "profile", ID: WorkspaceCapabilityID, Version: WorkspaceCapabilityVersion}
	effective := []authority.Fact{{ID: "workspace.read", Kind: "filesystem", Value: authority.FactValue{Access: "read", LogicalLocation: "workspace"}, Reason: "common_workspace", Source: source}}
	if contribution.access == launch.WorkspaceAccessReadWrite {
		effective = append(effective, authority.Fact{ID: "workspace.write", Kind: "filesystem", Value: authority.FactValue{Access: "write", LogicalLocation: "workspace"}, Reason: "common_workspace", Source: source})
	}
	return authority.Facts{Effective: effective}
}

type WorkspaceBinding = category.Binding[launch.WorkspaceAccess, launch.WorkspaceAccess, WorkspaceContribution]

func NewWorkspaceBinding() (WorkspaceBinding, error) {
	return category.Bind(category.Definition[launch.WorkspaceAccess, launch.WorkspaceAccess, WorkspaceContribution]{
		ID: WorkspaceCapabilityID, SchemaVersion: WorkspaceCapabilityVersion,
		Empty:       func() launch.WorkspaceAccess { return launch.WorkspaceAccessReadOnly },
		LegacyEmpty: func() launch.WorkspaceAccess { return launch.WorkspaceAccessReadWrite },
		Encode: func(access launch.WorkspaceAccess) (json.RawMessage, error) {
			return json.Marshal(struct {
				Access launch.WorkspaceAccess `json:"access"`
			}{access})
		},
		Decode: func(data json.RawMessage) (launch.WorkspaceAccess, error) {
			var value struct {
				Access launch.WorkspaceAccess `json:"access"`
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&value); err != nil {
				return "", err
			}
			if value.Access != launch.WorkspaceAccessReadOnly && value.Access != launch.WorkspaceAccessReadWrite {
				return "", errors.New("workspace access must be read-only or read-write")
			}
			return value.Access, nil
		},
		Resolve: func(_ context.Context, access launch.WorkspaceAccess) (launch.WorkspaceAccess, error) {
			return access, nil
		},
		ResolveSyntax: func(access launch.WorkspaceAccess) (launch.WorkspaceAccess, error) { return access, nil },
		Contribute: func(access launch.WorkspaceAccess) (WorkspaceContribution, error) {
			return WorkspaceContribution{access: access}, nil
		},
		Count: func(launch.WorkspaceAccess) int { return 0 },
	})
}

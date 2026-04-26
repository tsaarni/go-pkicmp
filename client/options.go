package client

import (
	"crypto/x509/pkix"
)

type requestOptions struct {
	sender          *pkix.Name
	templateSubject *pkix.Name
	templateExts    []pkix.Extension
}

// RequestOption configures a specific enrollment request.
type RequestOption func(*requestOptions)

// WithSender sets the sender name in the PKIHeader.
func WithSender(name pkix.Name) RequestOption {
	return func(o *requestOptions) { o.sender = &name }
}

// WithTemplateSubject sets the subject name in the CRMF CertTemplate.
func WithTemplateSubject(subject pkix.Name) RequestOption {
	return func(o *requestOptions) { o.templateSubject = &subject }
}

// WithTemplateExtension adds an extension to the CRMF CertTemplate.
func WithTemplateExtension(ext pkix.Extension) RequestOption {
	return func(o *requestOptions) { o.templateExts = append(o.templateExts, ext) }
}

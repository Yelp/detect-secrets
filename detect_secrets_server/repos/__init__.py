from .base_tracked_repo import BaseTrackedRepo
from .local_tracked_repo import LocalTrackedRepo
from .s3_tracked_repo import S3LocalTrackedRepo
from .s3_tracked_repo import S3TrackedRepo


def tracked_repo_factory(is_local=False, is_s3=False):
    if is_s3:
        if is_local:
            return S3LocalTrackedRepo
        else:
            return S3TrackedRepo
    else:
        if is_local:
            return LocalTrackedRepo
        else:
            return BaseTrackedRepo
